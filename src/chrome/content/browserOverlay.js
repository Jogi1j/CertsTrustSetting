Components.utils.import("resource://certstrustsetting/common.js");
Components.utils.import("resource://certstrustsetting/log4moz.js");


/**
 * CertsTrustSetting namespace.
 */
if ("undefined" == typeof(CertsTrustSetting)) {
  var CertsTrustSetting = {};
};

/**
 * Controls the browser overlay for the Certs Trust Setting extension.
 */
CertsTrustSetting.BrowserOverlay = {
  
  init : function() {
    // Init function for logging
    let formatter = new Log4Moz.BasicFormatter();
    let root = Log4Moz.repository.rootLogger;
    let logFile = this.getLocalDirectory(); // remember this?
    let appender;
    logFile.append("log.txt");
    
    // Loggers are hierarchical, lowering this log level will affect all
    // output.
    root.level = Log4Moz.Level["All"];
    
    // this appender will log to the file system.
    appender = new Log4Moz.RotatingFileAppender(logFile, formatter);
    appender.level = Log4Moz.Level["All"];
    root.addAppender(appender);
    
    // create logger
    this._logger = Log4Moz.repository.getLogger("CertsTrustSetting.SomeObject");
    this._logger.level = Log4Moz.Level["All"];
  },
  
  // Get number of certs in firefox
  getCountOfCerts : function() {
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);  
    var certs = certDB.getCerts();  
    var enumerator = certs.getEnumerator(); 
    var count = 0;
    
    while (enumerator.hasMoreElements()) {
      var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
        count++;      
    }
    return count;  
  },
  
  
  
  // Create local store for addon
  getLocalDirectory : function() {
    let directoryService =
      Cc["@mozilla.org/file/directory_service;1"].
        getService(Ci.nsIProperties);
    // this is a reference to the profile dir (ProfD) now.
    let localDir = directoryService.get("ProfD", Ci.nsIFile);
  
    localDir.append("CertsTrustSetting");
  
    if (!localDir.exists() || !localDir.isDirectory()) {
      // read and write permissions to owner and group, read-only for others.
      localDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0774);
    }
  
    return localDir;
  },
  
  
  
  getCertsToJson : function() {
    Components.utils.import("resource://gre/modules/NetUtil.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");
    
    // file is nsIFile, data is a string    
    var file  = this.getLocalDirectory();
    file.append("myCerts.json");
    var data = '{"certs":[';
    
    // get number of certs in firefox
    var count = this.getCountOfCerts();
    var i = 1;
    
    // write info from cert8.db
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    var certs = certDB.getCerts();
    var enumerator = certs.getEnumerator();
    while (enumerator.hasMoreElements()) {
      var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
      
      data = data + '\n{';
      data = data + '"certName":"' + cert.commonName + '"';
      data = data + ', "certType":"' + cert.certType + '"';
      if (cert.certType == 2) {
        data = data + ', "trustSetting":"u,u,u"';
      } else if (cert.certType == 8) {
        data = data + ', "trustSetting":"P,P,P"';
      } else {
        data = data + ', "trustSetting":"C,C,C"';
      }
      data = data + ', "organization":"' + cert.organization + '"';
      data = data + ', "serialNumber":"' + cert.serialNumber + '"';
      
      // last without a point
      if ( i == count ) {
        data = data + '}'
      } else {
        data = data + '},'
      }
      i++;    
    }
    
    data = data + '\n]}';
    
    // You can also optionally pass a flags parameter here. It defaults to
    // FileUtils.MODE_WRONLY | FileUtils.MODE_CREATE | FileUtils.MODE_TRUNCATE;
    var ostream = FileUtils.openSafeFileOutputStream(file);
    
    var converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].
                    createInstance(Ci.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";
    var istream = converter.convertToInputStream(data);
    
    // The last argument (the callback) is optional.
    NetUtil.asyncCopy(istream, ostream, function(status) {
      if (!Components.isSuccessCode(status)) {
        // Handle error!
        return;
      }
    
      // Data has been written to the file.
      file.create(Ci.nsIFile.NORMAL_FILE_TYPE, 0774);
    });
    
    window.alert("Export certifikátů proběhl vpořádku. \nVe složce profilu/CertsTrustSetting byl vytvořen soubor json.");
  },
  
  
  // Delete trust from all certs from certs.json
  cleanCerts : function() {
    var file = this.getLocalDirectory();
    file.append("certs.json");
    let url = "file://" + file.path;
    let request = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                  .createInstance(Components.interfaces.nsIXMLHttpRequest);
    request.onload = function(aEvent) {
      
      let text = aEvent.target.responseText;
      let jsonObject = JSON.parse(text);
      // Set certs
      var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
      var certs = certDB.getCerts();
      var enumerator = certs.getEnumerator();
      while (enumerator.hasMoreElements()) {
        var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
        for (i = 0; i < jsonObject.certs.length; i++) {
          if (cert.commonName == jsonObject.certs[i].certName
              && cert.organization == jsonObject.certs[i].organization
              && cert.serialNumber == jsonObject.certs[i].serialNumber) {
            certDB.setCertTrustFromString(cert,",,");
          }
        }     
      }
      window.alert("Odstraněna důvěra u všech certifikátů");
    };
    request.onerror = function(aEvent) {
      this._logger.error("Error Status: " + aEvent.target.status);
    };
    request.open("GET", url, true);
    request.send(null);
    this._logger.info("Metoda cleanCerts");
  },
  
  
  
  // Set trust all certs from certs.json back
  setCertsBack : function() {
    var file = this.getLocalDirectory();
    file.append("certs.json");
    let url = "file://" + file.path;
    let request = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                  .createInstance(Components.interfaces.nsIXMLHttpRequest);
    request.onload = function(aEvent) {
      let text = aEvent.target.responseText;
      let jsonObject = JSON.parse(text);
      
      // Set certs
      var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
      var certs = certDB.getCerts();
      var enumerator = certs.getEnumerator();
      while (enumerator.hasMoreElements()) {
        var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);       
        for (i = 0; i < jsonObject.certs.length; i++) {
          if (cert.commonName == jsonObject.certs[i].certName
              && cert.organization == jsonObject.certs[i].organization
              && cert.serialNumber == jsonObject.certs[i].serialNumber) {
            certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
          }
        }  
      }
      window.alert("Certifikáty nastaveny na výchozí hodnotu");
    };
    request.onerror = function(aEvent) {
       this._logger.error("Error Status: " + aEvent.target.status);
    };
    request.open("GET", url, true);
    request.send(null);
    this._logger.info("Metoda setCertsBack");
  },
  
  
  
  // Set Selection certs from certsSelection.json back
  setSelectionCertsBack : function() {
    var file = this.getLocalDirectory();
    file.append("certsSelection.json");
    let url = "file://" + file.path;
    let request = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                  .createInstance(Components.interfaces.nsIXMLHttpRequest);
    request.onload = function(aEvent) {
      let text = aEvent.target.responseText;
      let jsonObject = JSON.parse(text);
      
      // Set certs
      var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
      var certs = certDB.getCerts();
      var enumerator = certs.getEnumerator();
      while (enumerator.hasMoreElements()) {
        var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);       
        for (i = 0; i < jsonObject.certs.length; i++) {
          if (cert.commonName == jsonObject.certs[i].certName
              && cert.organization == jsonObject.certs[i].organization
              && cert.serialNumber == jsonObject.certs[i].serialNumber) {
            certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
          }
        }  
      }
      window.alert("Přidány certifikáty pouze z výběru");
    };
    request.onerror = function(aEvent) {
       this._logger.error("Error Status: " + aEvent.target.status);
    };
    request.open("GET", url, true);
    request.send(null);
    this._logger.info("Metoda setSelectionCertsBack");
  },
  
  
  
  // Set IMPORTANT certs from certsImportant.json back
  setImportantCertsBack : function() {
    var file = this.getLocalDirectory();
    file.append("certsImportant.json");
    let url = "file://" + file.path;
    let request = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                  .createInstance(Components.interfaces.nsIXMLHttpRequest);
    request.onload = function(aEvent) {
      let text = aEvent.target.responseText;
      let jsonObject = JSON.parse(text);
      
      // Set certs
      var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
      var certs = certDB.getCerts();
      var enumerator = certs.getEnumerator();
      while (enumerator.hasMoreElements()) {
        var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);       
        for (i = 0; i < jsonObject.certs.length; i++) {
          if (cert.commonName == jsonObject.certs[i].certName
              && cert.organization == jsonObject.certs[i].organization
              && cert.serialNumber == jsonObject.certs[i].serialNumber) {
            certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
          }
        }  
      }
      window.alert("Přidány pouze důležité certifikáty");
    };
    request.onerror = function(aEvent) {
       this._logger.error("Error Status: " + aEvent.target.status);
    };
    request.open("GET", url, true);
    request.send(null);
    this._logger.info("Metoda setImportantCertsBack");

  },
  
  
  
  // Load .json file for example
  loadJson : function() {
    var file = this.getLocalDirectory();
    file.append("certs.json");
    let url = "file://" + file.path;
    
    let request = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                  .createInstance(Components.interfaces.nsIXMLHttpRequest);
    request.onload = function(aEvent) {
      let text = aEvent.target.responseText;
      let jsonObject = JSON.parse(text);
    
      return jsonObject;
      //test
      //window.alert(jsonObject.certs[120].certName); 
    };
    request.onerror = function(aEvent) {
       this._logger.error("Error Status: " + aEvent.target.status);
    };
    request.open("GET", url, true);
    request.send(null);
  },
  

  
};





window.addEventListener(
  "load", function() { CertsTrustSetting.BrowserOverlay.init(); }, false);
