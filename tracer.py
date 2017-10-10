from burp import IBurpExtender
from burp import IParameter
from burp import ITab
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Font
from java.awt import GridLayout
from java.awt.event import ActionListener
from java.lang import Runnable
from java.lang import Thread
from java.net import URL
from javax.swing import BorderFactory
from javax.swing import ButtonGroup
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JProgressBar
from javax.swing import JScrollPane
from javax.swing import JTree
from javax.swing.border import EmptyBorder
from javax.swing.event import TreeModelEvent
from javax.swing.tree import TreeModel
from jarray import array

import json
import re
import urlparse

class Fonts:

    Heading = Font('Heading', Font.BOLD, 15)

class Colors:

    Orange = Color(229, 137, 0)

class Mode:

    InputToOutput = 0
    OutputToInput = 1

class NodeService:

    def __init__(self, callbacks, service):
        self.callbacks = callbacks
        self.service = service
        self.protocol = service.protocol
        self.host = service.host
        self.port = service.port
        self.endpoints = list()

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.host == other.host and self.port == other.port and self.protocol == other.protocol

    def __str__(self):
        return '{}://{}:{}'.format(self.protocol, self.host, self.port)

    def __hash__(self):
        return str(self).__hash__()

    def __repr__(self):
        return str(self)

class NodeEndpoint:

    def __init__(self, callbacks, url):
        self.callbacks = callbacks
        parsed = urlparse.urlparse(str(url))
        self.url = '{}://{}{}'.format(parsed.scheme, parsed.netloc, parsed.path)
        self.requests = list()

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.url == other.url

    def __str__(self):
        return self.url

    def __hash__(self):
        return str(self).__hash__()

    def __repr__(self):
        return urlparse.urlparse(self.url).path

class NodeRequest:

    def __init__(self, callbacks, request):
        self.callbacks = callbacks
        self.request = request
        self.parameters = list()
        self.dict = dict()
        for p in self.request.parameters:
            self.dict[p.name] = p.value

    def __dict__(self):
        return self.dict

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.request.method == other.request.method and self.request.url == other.request.url and self.dict == other.dict

    def __str__(self):
        return '{} {} ({})'.format(self.request.method, self.request.url, json.dumps(self.dict, sort_keys=True))

    def __hash__(self):
        return str(self).__hash__()

    def __repr__(self):
        return '{}: {}'.format(self.request.method, json.dumps(self.dict, sort_keys=True))

class NodeParameter:

    def __init__(self, callbacks, name, value):
        self.callbacks = callbacks
        self.name = name
        self.value = value
        self.references = list()

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.name == other.name and self.value == other.value

    def __str__(self):
        return '{}: {}'.format(self.name, self.value)

    def __hash__(self):
        return str(self).__hash__()

    def __repr__(self):
        return str(self)

class NodeReferenceService(NodeService):
    pass

class NodeReferenceEndpoint(NodeEndpoint):
    pass

class NodeReferenceRequest(NodeRequest):

    def __init__(self, callbacks, request):
        NodeRequest.__init__(self, callbacks, request)
        self.excerpts = list()

class NodeExcerpt:

    EXTRA_LEFT = 20
    EXTRA_RIGHT = 20

    def __init__(self, callbacks, offset, length, body):
        self.callbacks = callbacks
        self.offset = offset
        self.length = length
        self.data = body[offset:offset+length]
        start = max(0, offset - NodeExcerpt.EXTRA_LEFT)
        end = min(len(body), offset + length + NodeExcerpt.EXTRA_RIGHT)
        self.preview = '{}{}{}'.format('...' if start > 0 else '', body[start:end], '...' if end < len(body) else '')

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.offset == other.offset and self.length == other.length and self.data == other.data

    def __str__(self):
        return 'Offset: {}; Length: {}; Data: "{}"'.format(self.offset, self.length, self.preview)

    def __hash__(self):
        return str(self).__hash__()

    def __repr__(self):
        return str(self)

class TracerTreeModel(TreeModel):

    def __init__(self, extender, callbacks):
        self.extender = extender
        self.callbacks = callbacks
        self.services = list()
        self.listeners = list()

    def refresh(self):
        self.services = list()
        sitemap = self.callbacks.getSiteMap(None)
        inputs = 0
        self.extender.progressCallbackInput('Ready', inputs, len(sitemap))
        for pair in sitemap:
            # Compute session
            rq = self.callbacks.helpers.analyzeRequest(pair.httpService, pair.request)
            rp = self.callbacks.helpers.analyzeRequest(pair.response) if pair.response else None
            if self.callbacks.isInScope(URL(str(rq.url))) and rq.parameters:
                # Compute service
                service = NodeService(self.callbacks, pair.httpService)
                service = self.services[self.services.index(service)] if service in self.services else service
                # Compute endpoint
                endpoint = NodeEndpoint(self.callbacks, rq.url)
                endpoint = service.endpoints[service.endpoints.index(endpoint)] if endpoint in service.endpoints else endpoint
                # Compute request
                request = NodeRequest(self.callbacks, rq)
                request = endpoint.requests[endpoint.requests.index(request)] if request in endpoint.requests else request
                # Compute references
                outputs = 0
                self.extender.progressCallbackOutput('Ready', outputs, len(sitemap))
                for spair in sitemap:
                    # Compute subsession
                    srq = self.callbacks.helpers.analyzeRequest(spair.httpService, spair.request)
                    srp = self.callbacks.helpers.analyzeResponse(spair.response) if spair.response else None
                    if srp and self.callbacks.isInScope(URL(str(srq.url))):
                        # Look for parameters in body
                        body = spair.response.tostring()[srp.bodyOffset:]
                        for param in rq.parameters:
                            # Skip if not found
                            if param.value and param.value in body:
                                # Compute parameter
                                parameter = NodeParameter(self.callbacks, param.name, param.value)
                                parameter = request.parameters[request.parameters.index(parameter)] if parameter in request.parameters else parameter
                                # Compute referenced service
                                rservice = NodeReferenceService(self.callbacks, spair.httpService)
                                rservice = parameter.references[parameter.references.index(rservice)] if rservice in parameter.references else rservice
                                # Compute referenced endpoint
                                rendpoint = NodeReferenceEndpoint(self.callbacks, srq.url)
                                rendpoint = rservice.endpoints[rservice.endpoints.index(rendpoint)] if rendpoint in rservice.endpoints else rendpoint
                                # Compute referenced request
                                rrequest = NodeReferenceRequest(self.callbacks, srq)
                                rrequest = rendpoint.requests[rendpoint.requests.index(rrequest)] if rrequest in rendpoint.requests else rrequest
                                # Iterate over all excerpts
                                for match in re.finditer(re.escape(param.value), body):
                                    # Compute excerpt
                                    excerpt = NodeExcerpt(self.callbacks, match.start(), len(param.value), body)
                                    excerpt = rrequest.excerpts[rrequest.excerpts.index(excerpt)] if excerpt in rrequest.excerpts else excerpt
                                    # Install service
                                    if service not in self.services:
                                        self.services.append(service)
                                    # Install endpoint
                                    if endpoint not in service.endpoints:
                                        service.endpoints.append(endpoint)
                                    # Install request
                                    if request not in endpoint.requests:
                                        endpoint.requests.append(request)
                                    # Install parameter
                                    if parameter not in request.parameters:
                                        request.parameters.append(parameter)
                                    # Install referenced service
                                    if rservice not in parameter.references:
                                        parameter.references.append(rservice)
                                    # Install referenced endpoint
                                    if rendpoint not in rservice.endpoints:
                                        rservice.endpoints.append(rendpoint)
                                    # Install referenced request
                                    if rrequest not in rendpoint.requests:
                                        rendpoint.requests.append(rrequest)
                                    # Install excerpt
                                    if excerpt not in rrequest.excerpts:
                                        rrequest.excerpts.append(excerpt)
                    outputs += 1
                    self.extender.progressCallbackOutput('Inspecting Outputs [{}/{}]: {}'.format(outputs, len(sitemap), URL(str(srq.url))), outputs, len(sitemap))
            inputs += 1
            self.extender.progressCallbackInput('Inspecting Inputs [{}/{}]: {}'.format(inputs, len(sitemap), URL(str(rq.url))), inputs, len(sitemap))
        # Render tree
        for listener in self.listeners:
            listener.treeStructureChanged(TreeModelEvent(self, [self]))

    def getRoot(self):
        return self

    def getChild(self, parent, index):
        if parent is self:
            return parent.services[index]
        if parent.__class__ == NodeService:
            return parent.endpoints[index]
        if parent.__class__ == NodeEndpoint:
            return parent.requests[index]
        if parent.__class__ == NodeRequest:
            return parent.parameters[index]
        if parent.__class__ == NodeParameter:
            return parent.references[index]
        if parent.__class__ == NodeReferenceService:
            return parent.endpoints[index]
        if parent.__class__ == NodeReferenceEndpoint:
            return parent.requests[index]
        if parent.__class__ == NodeReferenceRequest:
            return parent.excerpts[index]
        return None

    def getChildCount(self, parent):
        if parent is self:
            return len(parent.services)
        if parent.__class__ == NodeService:
            return len(parent.endpoints)
        if parent.__class__ == NodeEndpoint:
            return len(parent.requests)
        if parent.__class__ == NodeRequest:
            return len(parent.parameters)
        if parent.__class__ == NodeParameter:
            return len(parent.references)
        if parent.__class__ == NodeReferenceService:
            return len(parent.endpoints)
        if parent.__class__ == NodeReferenceEndpoint:
            return len(parent.requests)
        if parent.__class__ == NodeReferenceRequest:
            return len(parent.excerpts)
        return 0

    def isLeaf(self, node):
        return self.getChildCount(node) <= 0

    def valueForPathChanged(self, path, value):
        pass

    def getIndexOfChild(self, parent, child):
        if parent is self:
            return parent.services.index(child)
        if parent.__class__ == NodeService:
            return parent.endpoints.index(child)
        if parent.__class__ == NodeEndpoint:
            return parent.requests.index(child)
        if parent.__class__ == NodeRequest:
            return parent.parameters.index(child)
        if parent.__class__ == NodeParameter:
            return parent.references.index(child)
        if parent.__class__ == NodeReferenceService:
            return parent.endpoints.index(child)
        if parent.__class__ == NodeReferenceEndpoint:
            return parent.requests.index(child)
        if parent.__class__ == NodeReferenceRequest:
            return parent.excerpts.index(child)
        return 0

    def addTreeModelListener(self, listener):
        self.listeners.append(listener)

    def removeTreeModeListener(self, listener):
        self.listeners.remove(listener)

    def __str__(self):
        return 'Tracer'

    def __repr__(self):
        return str(self)

class ResultTree(JTree):
    
    def __init__(self, extender):
        super(ResultTree, self).__init__()
        self.extender = extender
        self.rootVisible = False
        
    def refresh(self):
        self.model.refresh()

    def registerExtenderCallbacks(self, callbacks):
        self.model = TracerTreeModel(self.extender, callbacks)

class TitlePanel(JPanel):

    def __init__(self, extender):
        # Initialize self
        super(TitlePanel, self).__init__()
        self.extender = extender
        self.setLayout(GridLayout(2, 1))
        # Create children
        self.title = JLabel('Tracer')
        self.subtitle = JPanel()
        self.label = JLabel('Allows you to trace where inputs are reflected back to the user. Click "Start" to analyze the current site map.')
        # Configure children
        self.title.setFont(Fonts.Heading)
        self.title.setForeground(Colors.Orange)
        self.subtitle.layout.hgap = 0
        # Add children
        self.add(self.title)
        self.add(self.subtitle)
        self.subtitle.add(self.label)

    def refresh(self):
        pass

    def registerExtenderCallbacks(self, callbacks):
        pass

class StartActionListener(ActionListener):

    def __init__(self, extender):
        super(StartActionListener, self).__init__()
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.refresh()

class InfoActionListener(ActionListener):

    def __init__(self, extender):
        super(InfoActionListener, self).__init__()
        self.extender = extender

    def actionPerformed(self, event):
        JOptionPane.showMessageDialog(self.extender.master, '\n'.join([
            'Burp Tracer Version 1.0.0',
            '',
            'Written by John Lawrence M. Penafiel',
            '',
            'Blog: https://penafieljlm.com/',
            'GitHub: https://github.com/penafieljlm',
            'Twitter: https://twitter.com/penafieljlm',
            'LinkedIn: https://www.linkedin.com/in/penafieljlm',
        ]), 'Information - Burp Tracer 1.0.0', JOptionPane.INFORMATION_MESSAGE)

class ActionsPanel(JPanel):

    def __init__(self, extender):
        # Initialize self
        super(ActionsPanel, self).__init__()
        self.extender = extender
        self.setLayout(GridLayout(2, 1))
        # Create children
        self.title = JLabel('Actions')
        self.actions = JPanel(GridLayout(1, 3))
        self.start = JButton('Start')
        self.info = JButton('Info')
        # Configure children
        self.title.setFont(Fonts.Heading)
        self.title.setForeground(Colors.Orange)
        self.actions.layout.vgap = 0
        self.actions.layout.hgap = 0
        self.start.addActionListener(StartActionListener(extender))
        self.info.addActionListener(InfoActionListener(extender))
        # Add children
        self.add(self.title)
        self.add(self.actions)
        self.actions.add(self.start)
        self.actions.add(self.info)

    def refresh(self):
        pass

    def registerExtenderCallbacks(self, callbacks):
        pass

class HeadPanel(JPanel):

    def __init__(self, extender):
        # Initialize self
        super(HeadPanel, self).__init__()
        self.extender = extender
        self.setLayout(BorderLayout())
        self.setBorder(EmptyBorder(10, 10, 10, 10))
        # Create children
        self.title = TitlePanel(extender)
        self.actions = ActionsPanel(extender)
        # Add children
        self.add(self.title, BorderLayout.WEST)
        self.add(self.actions, BorderLayout.EAST)

    def refresh(self):
        self.title.refresh()
        self.actions.refresh()

    def registerExtenderCallbacks(self, callbacks):
        self.title.registerExtenderCallbacks(callbacks)
        self.actions.registerExtenderCallbacks(callbacks)

class MainPanel(JPanel):

    def __init__(self, extender):
        # Initialize self
        super(MainPanel, self).__init__()
        self.extender = extender
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        # Create children
        self.tree = ResultTree(extender)
        # Add children
        self.add(JScrollPane(self.tree), BorderLayout.CENTER)

    def refresh(self):
        self.tree.refresh()

    def registerExtenderCallbacks(self, callbacks):
        self.tree.registerExtenderCallbacks(callbacks)

class FooterPanel(JPanel):

    def __init__(self, extender):
        # Initialize self
        super(FooterPanel, self).__init__()
        self.extender = extender
        self.setLayout(GridLayout(2, 1))
        # Create children
        self.progressInput = JProgressBar(0, 10000)
        self.progressOutput = JProgressBar(0, 10000)
        self.credit = JPanel()
        # Configure children
        self.progressInput.string = 'Ready'
        self.progressOutput.string = 'Ready'
        self.progressInput.stringPainted = True
        self.progressOutput.stringPainted = True
        # Add children
        self.add(self.progressInput)
        self.add(self.progressOutput)

    def refresh(self):
        pass

    def registerExtenderCallbacks(self, callbacks):
        pass

class MasterPanel(JPanel):

    def __init__(self, extender):
        # Initialize Self
        super(MasterPanel, self).__init__()
        self.extender = extender
        self.setLayout(BorderLayout())
        # Create children
        self.head = HeadPanel(extender)
        self.main = MainPanel(extender)
        self.foot = FooterPanel(extender)
        # Add children
        self.add(self.head, BorderLayout.NORTH)
        self.add(self.main, BorderLayout.CENTER)
        self.add(self.foot, BorderLayout.SOUTH)

    def refresh(self):
        self.head.refresh()
        self.main.refresh()
        self.foot.refresh()

    def registerExtenderCallbacks(self, callbacks):
        self.head.registerExtenderCallbacks(callbacks)
        self.main.registerExtenderCallbacks(callbacks)
        self.foot.registerExtenderCallbacks(callbacks)

class RefreshRunnable(Runnable):

    def __init__(self, extender):
        self.extender = extender

    def run(self):
        self.extender.processStart()
        self.extender.master.refresh()
        self.extender.processEnd()

class BurpExtender(IBurpExtender, ITab):

    def __init__(self):
        self.name = 'Tracer'
        self.master = None
        self.master = MasterPanel(self)

    def processStart(self):
        self.master.head.actions.start.enabled = False
        self.progressCallbackInput('Ready', 0, 1)
        self.progressCallbackOutput('Ready', 0, 1)

    def processEnd(self):
        self.master.head.actions.start.enabled = True
        self.progressCallbackInput('Done', 1, 1)
        self.progressCallbackOutput('Done', 1, 1)

    def progressCallbackInput(self, string, current, maximum):
        self.master.foot.progressInput.string = string
        self.master.foot.progressInput.value = int(10000.0 * (float(current) / float(maximum)))

    def progressCallbackOutput(self, string, current, maximum):
        self.master.foot.progressOutput.string = string
        self.master.foot.progressOutput.value = int(10000.0 * (float(current) / float(maximum)))

    def refresh(self):
        thread = Thread(RefreshRunnable(self))
        thread.start()

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('Tracer')
        callbacks.addSuiteTab(self)
        self.master.registerExtenderCallbacks(callbacks)

    def getTabCaption(self):
        return self.name

    def getUiComponent(self):
        return self.master