Components.utils.import("resource://certstrustsetting/common.js");
//Components.utils.import("resource://certstrustsetting/messageCount.js");
Components.utils.import("resource://certstrustsetting/log4moz.js");


/**
 * CertsTrustSetting namespace.
 */
if ("undefined" == typeof(CertsTrustSetting)) {
  var CertsTrustSetting = {};
};

/**
 * Controls the browser overlay for the Hello World extension.
 */
CertsTrustSetting.BrowserOverlay = {
  
  init : function() {
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
    
    // vytvoření
    this._logger = Log4Moz.repository.getLogger("CertsTrustSetting.SomeObject");
    this._logger.level = Log4Moz.Level["All"];
 
  },
  viewCerts : function() {
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);  
    var certs = certDB.getCerts();  
    var enumerator = certs.getEnumerator(); 
    var s = "";
    var count = 0;
    var certsAlertText = "Náhled všech certifikátů, VČETNĚ NEDŮVĚRYHODNÝCH: \n";
    
    while (enumerator.hasMoreElements()) {
      var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
      
      //window.alert(cert.tokenName);  
      //if (cert.issuerCommonName != "" ) {
        certsAlertText = certsAlertText + " \n " +  cert.issuerCommonName;
        count++;
      //}
      //if (cert.commonName != "") {
      //  
      //}
      
    }
    certsAlertText = count + " certifikátů \n" + certsAlertText;    
    window.alert(certsAlertText);
  },
  
  
  // Export all certifications
  exportCerts: function() {
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    var certs = certDB.getCerts();
    var enumerator = certs.getEnumerator();
    var s = "";
    var count = 0;
    var certArray = [];
    while (enumerator.hasMoreElements()) {
      var cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
      
      //if (cert.commonName != "") {
        count++;
        certArray[count] = cert;
        //certArray[count] = cert.issuer;
        //certArray[count] = certs.getChain();
      //}
    }

    // Pokus 2 přes getLocalDirextory
    let exportDB = this.getLocalDirectory();
    exportDB.append("certifikaty");
    var pokus = [];
    pokus[0] = certArray[cislo];
        
    //certDB.exportPKCS12File(null,exportDB,0,[]); //works !!
    //certDB.exportPKCS12File(null,exportDB,1,pokus);
    certDB.exportPKCS12File(null,exportDB,count,certArray);
    
    if (!exportDB.exists() || !exportDB.isDirectory()) {
      // read and write permissions to owner and group, read-only for others.
      exportDB.create(Ci.nsIFile.NORMAL_FILE_TYPE, 0774);
    }     
    window.alert("Export " + count + " certifikátů.");
  },
  
  
  
  // Import certifications
  importCerts: function() {
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    
    // pokus 1
    let file = this.getLocalDirectory();
    file.append("addons.mozilla.org.pfx");
    
    //certDB.importCertsFromFile(null,file,CA_CERT);
    //certDB.importPKCS12File(null,file);
    //certDB.addCertFromBase64(cert, CertTrust, "");
    //certDB.addCertFromBase64(cert, CertTrust, "");
    
    window.alert("import cert done");
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
        //if (cert.commonName == "addons.mozilla.org") {
        //    window.alert("\n Server: " + cert.certType);
        //    certDB.setCertTrust(cert, SERVER_CERT, "CT,CT,CT");
        //    //certDB.setCertTrustFromString(cert,",,");
        //  }
        //  if (cert.commonName == "Visa eCommerce Root") {
        //    window.alert("\n CA: "  + cert.certType);
        //    
        //  } 
        for (i = 0; i < jsonObject.certs.length; i++) {
          if (cert.commonName == "" ) {
            if (cert.organization == jsonObject.certs[i].organization) {
              if (cert.serialNumber == "00"){
                if (cert.organizationalUnit == jsonObject.certs[i].organizationalUnit){
                  certDB.setCertTrustFromString(cert,",,");
                }
              }else if (cert.serialNumber == jsonObject.certs[i].serialNumber){      
                certDB.setCertTrustFromString(cert,",,");
              }
            }
          } else if (cert.commonName == jsonObject.certs[i].certName) {
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
          if (cert.commonName == "" ) {
            if (cert.organization == jsonObject.certs[i].organization) {
              if (cert.serialNumber == "00"){
                if (cert.organizationalUnit == jsonObject.certs[i].organizationalUnit){
                  certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
                }
              }else if (cert.serialNumber == jsonObject.certs[i].serialNumber){
                certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
              }
            }
          } else if (cert.commonName == jsonObject.certs[i].certName) {
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
          if (cert.commonName == "" ) {
            if (cert.organization == jsonObject.certs[i].organization) {
              if (cert.serialNumber == "00"){
                if (cert.organizationalUnit == jsonObject.certs[i].organizationalUnit){
                  certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
                }
              }else if (cert.serialNumber == jsonObject.certs[i].serialNumber){
                certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
              }
            }
          } else if (cert.commonName == jsonObject.certs[i].certName) {
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
          if (cert.commonName == "" ) {
            if (cert.organization == jsonObject.certs[i].organization) {
              if (cert.serialNumber == "00"){
                if (cert.organizationalUnit == jsonObject.certs[i].organizationalUnit){
                  certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
                }
              }else if (cert.serialNumber == jsonObject.certs[i].serialNumber){
                certDB.setCertTrustFromString(cert,jsonObject.certs[i].trustSetting);
              }
            }
          } else if (cert.commonName == jsonObject.certs[i].certName) {
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
  
  // Load .json file
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
  }
};


window.addEventListener(
  "load", function() { CertsTrustSetting.BrowserOverlay.init(); }, false);
