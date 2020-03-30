# -*- coding:utf-8 -*-
# Author: Vulkey_Chen
# Blog: gh0st.cn
# Team: MSTSEC

import json, re, jsbeautifier

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel, JLabel, JButton, JTextArea, JTextField, JCheckBox, JTabbedPane, JScrollPane, SwingConstants
from java.awt import BorderLayout

from java.io import PrintWriter

# color list
colors = ['red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'magenta', 'gray']

# config
configFile = "config.json"

# 获取配置文件内容
def getConfig():
    config = ""
    with open(configFile, 'r') as content:
        config = json.load(content)
    return config

# 寻找内容
def findContent(info, message):
    info = getConfig()
    results = {}
    for i in info:
        regex = re.compile(info[i]['regex'])
        regexRes = regex.findall(message)
        if regexRes != []:
            results[i] = ','.join(list(set(regexRes)))
    return results

class BurpExtender(IBurpExtender, ITab,IHttpListener, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HaE(Highlighter and Extractor)")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        print 'HaE(Highlighter and Extractor)\nAuthor: Vulkey_Chen\nBlog: gh0st.cn\nTeam: MSTSEC'
        self._callbacks.customizeUiComponent(self.getUiComponent())
        self._callbacks.addSuiteTab(self)
        self.endColors = []

    def getTabCaption(self):
        return 'HaE'

    def createNewInstance(self, controller, editable):
        return MarkINFOTab(self, controller, editable)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        content = messageInfo.getResponse()
        # content 为响应正文信息
        info = getConfig()
        results = findContent(info, content)
        colorList = []
        if results != {}:
            for i in results:
                if info[i]['highlight'] == 1 :
                    if info[i]['color'] == 'red':
                        messageInfo.setHighlight(info[i]['color'])
                        break
                    else:
                        colorList.append(info[i]['color'])

            if not messageInfo.getHighlight():
                colorsList = [colors.index(i) for i in colorList]
                colorsList.sort()
                # print(colorsList)
                self.helper(colorsList)
                endColor = [colors.index(x) for x in self.endColors]
                # print(endColor)
                messageInfo.setHighlight(colors[min(endColor)])

    # 颜色升级
    def helper(self, mylist):
        l = len(mylist)
        i = 0
        stack = []
        while i < l:
            if not stack:
                stack.append(mylist[i])
                i += 1
            else:
                if mylist[i] != stack[-1]:
                    stack.append(mylist[i])
                    i += 1
                else:
                    stack[-1] -= 1
                    i += 1

        if len(stack) == len(set(stack)):
            self.endColors = [colors[i] for i in stack]
        else:
            self.helper(stack)

    def addConfig(self, event):
        nameText = self.nameTextField.getText()
        regexText = self.regexTextField.getText()
        colorText = self.colorTextField.getText()
        isHighlight = int(self.highlightCheckBox.isSelected())
        isExtract = int(self.extractCheckBox.isSelected())
        if colorText in colors:
            with open(configFile, 'r+') as content:
                dicts = json.load(content)
                if nameText in dicts:
                    self.tipString.setText("Name is existed!")
                elif not(isHighlight or isExtract):
                    self.tipString.setText("Highlight or Extract?")
                else:
                    # 解决r+写入问题
                    content.seek(0,0)
                    content.truncate()
                    dicts[nameText] = {"regex": regexText, "highlight": isHighlight, "extract": isExtract, "color": colorText}
                    content.write(jsbeautifier.beautify(json.dumps(dicts)))
                    #print(dicts)
                    self.tipString.setText("Save Successfully!")
        else:
            self.tipString.setText("Not in colors list.")

    def reloadConfig(self, event):
        # 重新载入配置文件
        with open(configFile, 'r') as content:
            self.configTextArea.setText(content.read())

    def saveConfig(self, event):
        # 保存配置文件
        text = self.configTextArea.getText()
        if text != "":
            with open(configFile, 'w') as content:
                content.write(text)
            self.reloadConfig()

    def getUiComponent(self):
        self.HaEPanel = JPanel()
        self.HaEPanel.setBorder(None)
        self.HaEPanel.setLayout(BorderLayout(0, 0))
        self.panel = JPanel()
        self.HaEPanel.add(self.panel, BorderLayout.NORTH)
        self.panel.setLayout(BorderLayout(0, 0))
        self.tabbedPane = JTabbedPane(JTabbedPane.TOP)
        self.panel.add(self.tabbedPane, BorderLayout.CENTER)
        self.setPanel = JPanel()
        self.tabbedPane.addTab("Set", None, self.setPanel, None)
        self.setPanel.setLayout(BorderLayout(0, 0))
        self.setPanel_1 = JPanel()
        self.setPanel.add(self.setPanel_1, BorderLayout.NORTH)
        self.nameString = JLabel("Name")
        self.setPanel_1.add(self.nameString)
        self.nameTextField = JTextField()
        self.setPanel_1.add(self.nameTextField)
        self.nameTextField.setColumns(10)
        self.regexString = JLabel("Regex")
        self.setPanel_1.add(self.regexString)
        self.regexTextField = JTextField()
        self.setPanel_1.add(self.regexTextField)
        self.regexTextField.setColumns(10)
        self.extractCheckBox = JCheckBox("Extract")
        self.setPanel_1.add(self.extractCheckBox)
        self.highlightCheckBox = JCheckBox("Highlight")
        self.setPanel_1.add(self.highlightCheckBox)
        self.setPanel_2 = JPanel()
        self.setPanel.add(self.setPanel_2)
        self.colorString = JLabel("Color")
        self.setPanel_2.add(self.colorString)
        self.colorTextField = JTextField()
        self.setPanel_2.add(self.colorTextField)
        self.colorTextField.setColumns(5)
        self.addBottun = JButton("Add", actionPerformed=self.addConfig)
        self.setPanel_2.add(self.addBottun)
        self.tipString = JLabel("");
        self.setPanel_2.add(self.tipString)
        self.configPanel = JPanel()
        self.tabbedPane.addTab("Config", None, self.configPanel, None)
        self.configPanel.setLayout(BorderLayout(0, 0))
        self.configTextArea = JTextArea()
        # self.configTextArea.setEnabled(False)
        self.configTextArea.setTabSize(4)
        self.configTextArea.setLineWrap(True)
        self.configTextArea.setRows(20)
        self.configPanel.add(self.configTextArea, BorderLayout.SOUTH)
        self.scrollPane = JScrollPane(self.configTextArea)
        self.configPanel.add(self.scrollPane, BorderLayout.SOUTH)
        self.reloadButton = JButton("Reload", actionPerformed=self.reloadConfig)
        self.configPanel.add(self.reloadButton, BorderLayout.NORTH)
        self.saveButton = JButton("Save", actionPerformed=self.saveConfig)
        self.configPanel.add(self.saveButton, BorderLayout.CENTER)
        return self.HaEPanel
        
class MarkINFOTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

    def getTabCaption(self):
        return "MarkINFO"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    # 非响应 没有匹配到不返回Tab标签页
    def isEnabled(self, content, isRequest):
        info = getConfig()
        if not isRequest:
            contents = findContent(info, content)
            if contents != {}:
                for i in contents:
                    if info[i]['extract'] == 1 :
                        return True

    # 设置Tab的内容
    def setMessage(self, content, isRequest):
        # 判断是否有内容
        if content:
            if not isRequest:
                info = getConfig()
                contents = findContent(info, content)
                result = ""
                for i in contents:
                    if info[i]['extract'] == 1 :
                        result += "[{}] {}\n".format(i,contents[i])
                self._txtInput.setText(result)
        else:
            return False