from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from javax.swing.table import DefaultTableModel;
from javax.swing import JDialog
from javax.swing.event import ListSelectionListener
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditorController
from org.python.core.util import StringUtil

import re
import replacements
import uuid

class MessageEditorController(IMessageEditorController):
    def setRequestResponse(self,requestResponse):
        self.requestResponse = requestResponse

    def getHttpService(self):

        if self.requestResponse:
            return self.requestResponse.getHttpService()
        return None

    def getRequest(self):
        if self.requestResponse:
            return self.requestResponse.getRequest()
        return None

    def getResponse(self):
        if self.requestResponse:
            return self.requestResponse.getResponse()
        return None


class Plugin(IHttpListener):

    MUTATE_ID_COLUMN_INDEX=4
    ORIG_ID_COLUMN_INDEX=5

    def __init__(self,callbacks):
        self.callbacks = callbacks
        self.helpers = self.callbacks.getHelpers()

        self.origMessageEditorController = MessageEditorController()
        self.mutatedMessageEditorController = MessageEditorController()

        self.origSearchString = replacements.origSearchString
        self.replacements = replacements.replacements

        self.requestResponseCache = {}

    def start(self):


        self.frame = JDialog()
        #self.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
        self.frame.setLocation(0,1500)
        self.frame.setSize(1000,200)

        self.tableDataModel = DefaultTableModel([], ["URL","Code","Content-Length","Location","Mutated Id","Orig Id"])
        self.jtable = JTable(self.tableDataModel)

        scrollPane = JScrollPane(self.jtable);
        self.jtable.setFillsViewportHeight(True)

       


        messageEditorOrig = self.callbacks.createMessageEditor(None,False);
        messageEditorModified = self.callbacks.createMessageEditor(None,False);
        self.editorSplitPane =  JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                messageEditorOrig.getComponent(),
                messageEditorModified.getComponent())
        self.editorSplitPane.setResizeWeight(0.5);

        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           scrollPane,self.editorSplitPane);
        splitPane.setResizeWeight(0.5);

        class TableSelector(ListSelectionListener):
            def __init__(self,plugin):
                self.plugin = plugin

            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    selectedRowIndex = self.plugin.jtable.getSelectedRows()[0]

                    self.plugin._rowSelected(selectedRowIndex)
            
        self.jtable.getSelectionModel().addListSelectionListener(TableSelector(self))



        self.frame.add(splitPane)
        self.frame.setVisible(True)

        self.callbacks.registerHttpListener(self)
        self.callbacks.setExtensionName("Custom Plugin")
        return
    
    def stop(self):

        print("Closing!")
        self.callbacks.removeHttpListener(self)
        self.frame.dispose()
        self.jrame = None
        return

    def _rowSelected(self,index):

        #self.splitPane.setLeftComponent(
        #self.callbacks.createMessageEditor(
        origId = self.tableDataModel.getValueAt(index,self.ORIG_ID_COLUMN_INDEX).encode('ascii','ignore')
        mutateId = self.tableDataModel.getValueAt(index,self.MUTATE_ID_COLUMN_INDEX).encode('ascii','ignore')


        self.origMessageEditorController.setRequestResponse(self.requestResponseCache[origId])
        messageEditorOrig = self.callbacks.createMessageEditor(self.origMessageEditorController,False);
        messageEditorOrig.setMessage(self.requestResponseCache[origId].getResponse(),False)
        self.editorSplitPane.setLeftComponent(messageEditorOrig.getComponent())

        self.mutatedMessageEditorController.setRequestResponse(self.requestResponseCache[mutateId])
        messageEditorMutated = self.callbacks.createMessageEditor(self.mutatedMessageEditorController,False);
        messageEditorMutated.setMessage(self.requestResponseCache[mutateId].getResponse(),False)
        self.editorSplitPane.setRightComponent(messageEditorMutated.getComponent())
        
        print(mutateId)
        print("Row selected")
        print(str(index))


    def _buildResponseHeadersDictionary(self,headers):
        """Creates key/value lookup from list of headers.
           Header names are converted to lowercase.
           If header is returned multiple time, last header has precedence."""
        d = {}

        #Skip first "header", it's the response code line.
        for i in range(1,len(headers)):

            (name,value) = headers[i].split(":",1)
            d[name.lower()] = value

        return d

    def _getDictValueOrEmptyStr(self,d,key):
        if key in d:
            return d[key]
        else:
            return ""

    def handleReceivedResponseForModifiedRequest(self, requestResponse):


        #Get original HTTP Request
        requestData = StringUtil.fromBytes(requestResponse.getRequest())
        requestId = re.search(b"^X-REQUEST-ID: ([^\r]*)",requestData,flags=re.MULTILINE).group(1).encode('ascii')
        origRequestId = re.search(b"^X-REQUEST-ORIG-ID: ([^\r]*)",requestData,flags=re.MULTILINE).group(1).encode('ascii')

        print("Keys")
        print(requestId)
        print(origRequestId)
        print(self.requestResponseCache.keys())



        self.requestResponseCache[requestId]=requestResponse

        origRequestResponse = self.requestResponseCache[origRequestId]

        analyzedOrigResponse = self.helpers.analyzeResponse(origRequestResponse.getResponse())
        analayzeMutatedResponse = self.helpers.analyzeResponse(requestResponse.getResponse())

        origResponseHeaders=self._buildResponseHeadersDictionary(analyzedOrigResponse.getHeaders())
        mutatedResponseHeaders=self._buildResponseHeadersDictionary(analayzeMutatedResponse.getHeaders())


        mutatedRequestInfo=self.helpers.analyzeRequest(requestResponse.getHttpService(),requestResponse.getRequest())

        model=self.jtable.getModel()
        model.addRow([
            str(mutatedRequestInfo.getUrl()),
            str(analayzeMutatedResponse.getStatusCode()),
            self._getDictValueOrEmptyStr(mutatedResponseHeaders,"content-length"),
            self._getDictValueOrEmptyStr(mutatedResponseHeaders,"location"),
            requestId,
            origRequestId])
            


        print("Modified Request Found: %s %s" % (requestId, origRequestId))

        #Get original request and response object from lookup
        #Get request from lookup
        

    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):
        if not messageIsRequest:
            requestData = StringUtil.fromBytes(requestResponse.getRequest())


            #We generated the request, process it
            if requestData.find(b"X-REQUEST-ID") != -1:

                self.handleReceivedResponseForModifiedRequest(requestResponse)

            #Response received for non-mutated request.
            #Mutate request and send it.
            else:

                origRequestResponseUUID=str(uuid.uuid4())
                reload(replacements)

                print("Looking for replacements")
                for replacement in self.replacements:
                    newRequestData = re.sub(self.origSearchString,replacement,requestData)

                    #If no replacemnets made, don't send any requests
                    if newRequestData != requestData:
                        newRequestUUID = str(uuid.uuid4())
                        newRequestData=re.sub(b"Host",b"X-REQUEST-ID: " + newRequestUUID + "\r\nHost",requestData)
                        newRequestData=re.sub(b"Host",b"X-REQUEST-ORIG-ID: "+ origRequestResponseUUID+"\r\nHost",newRequestData)

                        print("Sending Mutated Request")
                        print(newRequestData)

                        self.requestResponseCache[origRequestResponseUUID]=requestResponse
                        httpService = requestResponse.getHttpService()
                        self.callbacks.makeHttpRequest(httpService,newRequestData)


            print("Got here")
