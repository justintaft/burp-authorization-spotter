from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from threading import Lock
import os.path, time
import plugin

class BurpExtender(IBurpExtender, IHttpListener):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object


        
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()
        self.plugin = None
        self.modifiedTime = 0

        self.reloadPluginIfNeeded()
        self.callbacks.registerHttpListener(self)


        return
        

    def reloadPluginIfNeeded(self):
        modifiedTime = os.path.getmtime("plugin.py")
        if(modifiedTime > self.modifiedTime):
            if(self.plugin):
                try:
                    self.plugin.stop()
                except: 
                    print("Exception occured")
                self.plugin = None

            reload(plugin)
            self.modifiedTime = modifiedTime
            self.plugin = plugin.Plugin(self.callbacks)
            self.plugin.start()
    
    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):

        self.reloadPluginIfNeeded()
