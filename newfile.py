# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'file.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIcon

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 602)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.send_file = QtWidgets.QPushButton(self.centralwidget)
        self.send_file.setGeometry(QtCore.QRect(30, 20, 111, 31))
        self.send_file.setCursor(QtGui.QCursor(QtCore.Qt.OpenHandCursor))
        self.send_file.setStyleSheet("background-color: rgb(85, 255, 127);")
        self.send_file.setObjectName("send_file")
        self.receive_file = QtWidgets.QPushButton(self.centralwidget)
        self.receive_file.setGeometry(QtCore.QRect(170, 20, 111, 31))
        self.receive_file.setStyleSheet("background-color: rgb(85, 255, 127);")
        self.receive_file.setObjectName("receive_file")
        self.stackedWidget = QtWidgets.QStackedWidget(self.centralwidget)
        self.stackedWidget.setGeometry(QtCore.QRect(10, 60, 781, 531))
        self.stackedWidget.setObjectName("stackedWidget")
        self.page = QtWidgets.QWidget()
        self.page.setObjectName("page")
        self.current_status_bar = QtWidgets.QProgressBar(self.page)
        self.current_status_bar.setGeometry(QtCore.QRect(140, 320, 610, 31))
        self.current_status_bar.setProperty("value", 0)
        self.current_status_bar.setObjectName("current_status_bar")
        self.line = QtWidgets.QFrame(self.page)
        self.line.setGeometry(QtCore.QRect(20, 360, 731, 21))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.total_status_bar = QtWidgets.QProgressBar(self.page)
        self.total_status_bar.setGeometry(QtCore.QRect(140, 390, 610, 31))
        self.total_status_bar.setProperty("value", 0)
        self.total_status_bar.setObjectName("total_status_bar")
        self.current_status = QtWidgets.QLabel(self.page)
        self.current_status.setGeometry(QtCore.QRect(20, 320, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.current_status.setFont(font)
        self.current_status.setObjectName("current_status")
        self.total_status = QtWidgets.QLabel(self.page)
        self.total_status.setGeometry(QtCore.QRect(20, 390, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.total_status.setFont(font)
        self.total_status.setObjectName("total_status")
        self.IP = QtWidgets.QLabel(self.page)
        self.IP.setGeometry(QtCore.QRect(20, 440, 41, 21))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.IP.setFont(font)
        self.IP.setObjectName("IP")
        self.IP_text = QtWidgets.QLineEdit(self.page)
        self.IP_text.setGeometry(QtCore.QRect(60, 440, 231, 31))
        self.IP_text.setObjectName("IP_text")
        self.PORT = QtWidgets.QLabel(self.page)
        self.PORT.setGeometry(QtCore.QRect(330, 440, 54, 21))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.PORT.setFont(font)
        self.PORT.setObjectName("PORT")
        self.PORT_text = QtWidgets.QLineEdit(self.page)
        self.PORT_text.setGeometry(QtCore.QRect(400, 440, 191, 31))
        self.PORT_text.setObjectName("PORT_text")
        self.text_file = QtWidgets.QLabel(self.page)
        self.text_file.setGeometry(QtCore.QRect(20, 20, 91, 31))
        font = QtGui.QFont()
        font.setPointSize(13)
        self.text_file.setFont(font)
        self.text_file.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.text_file.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.text_file.setObjectName("text_file")
        self.add_file = QtWidgets.QPushButton(self.page)
        self.add_file.setGeometry(QtCore.QRect(480, 10, 91, 41))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.add_file.setFont(font)
        self.add_file.setStyleSheet("background-color: rgb(170, 255, 0);")
        self.add_file.setObjectName("add_file")
        self.delete_file = QtWidgets.QPushButton(self.page)
        self.delete_file.setGeometry(QtCore.QRect(580, 10, 91, 41))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.delete_file.setFont(font)
        self.delete_file.setStyleSheet("background-color: rgb(255, 255, 0);")
        self.delete_file.setObjectName("delete_file")
        self.empty_file = QtWidgets.QPushButton(self.page)
        self.empty_file.setGeometry(QtCore.QRect(680, 10, 91, 41))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.empty_file.setFont(font)
        self.empty_file.setStyleSheet("background-color: rgb(255, 0, 127);")
        self.empty_file.setObjectName("empty_file")
        self.handler = QtWidgets.QPushButton(self.page)
        self.handler.setGeometry(QtCore.QRect(370, 480, 130, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.handler.setFont(font)
        self.handler.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.handler.setObjectName("handler")
        self.send = QtWidgets.QPushButton(self.page)
        self.send.setGeometry(QtCore.QRect(520, 480, 91, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.send.setFont(font)
        self.send.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.send.setObjectName("send")
        self.cancel = QtWidgets.QPushButton(self.page)
        self.cancel.setGeometry(QtCore.QRect(640, 480, 91, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cancel.setFont(font)
        self.cancel.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.cancel.setObjectName("cancel")
        self.status_show = QtWidgets.QLabel(self.page)
        self.status_show.setGeometry(QtCore.QRect(20, 490, 271, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.status_show.setFont(font)
        self.status_show.setText("")
        self.status_show.setObjectName("status_show")
        self.tableWidget = QtWidgets.QTableWidget(self.page)
        self.tableWidget.setGeometry(QtCore.QRect(10, 60, 741, 251))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setStyleSheet("")
        self.tableWidget.setLineWidth(1)
        self.tableWidget.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.tableWidget.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.tableWidget.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setRowCount(6)
        item = QtWidgets.QTableWidgetItem()
        item.setBackground(QtGui.QColor(170, 255, 127))
        self.tableWidget.setVerticalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        item.setBackground(QtGui.QColor(170, 255, 127))
        self.tableWidget.setVerticalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        item.setBackground(QtGui.QColor(170, 255, 127))
        self.tableWidget.setVerticalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setVerticalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        self.tableWidget.setHorizontalHeaderItem(1, item)
        self.tableWidget.horizontalHeader().setDefaultSectionSize(360)
        self.tableWidget.horizontalHeader().setMinimumSectionSize(20)
        self.tableWidget.verticalHeader().setDefaultSectionSize(50)
        self.tableWidget.verticalHeader().setVisible(False)
        self.stackedWidget.addWidget(self.page)
        self.page_2 = QtWidgets.QWidget()
        self.page_2.setObjectName("page_2")
        self.receive_status = QtWidgets.QLabel(self.page_2)
        self.receive_status.setGeometry(QtCore.QRect(30, 400, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.receive_status.setFont(font)
        self.receive_status.setObjectName("receive_status")
        self.receive_bar = QtWidgets.QProgressBar(self.page_2)
        self.receive_bar.setGeometry(QtCore.QRect(140, 400, 625, 31))
        self.receive_bar.setProperty("value", 0)
        self.receive_bar.setObjectName("receive_bar")
        self.line_2 = QtWidgets.QFrame(self.page_2)
        self.line_2.setGeometry(QtCore.QRect(30, 430, 721, 31))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.receive = QtWidgets.QPushButton(self.page_2)
        self.receive.setGeometry(QtCore.QRect(510, 480, 121, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.receive.setFont(font)
        self.receive.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.receive.setObjectName("receive")
        self.receive_cancel = QtWidgets.QPushButton(self.page_2)
        self.receive_cancel.setGeometry(QtCore.QRect(640, 480, 121, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.receive_cancel.setFont(font)
        self.receive_cancel.setStyleSheet("background-color: rgb(0, 170, 255);")
        self.receive_cancel.setObjectName("receive_cancel")
        self.IP_receive = QtWidgets.QLabel(self.page_2)
        self.IP_receive.setGeometry(QtCore.QRect(30, 450, 41, 21))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.IP_receive.setFont(font)
        self.IP_receive.setObjectName("IP_receive")
        self.IP_receive_text = QtWidgets.QLineEdit(self.page_2)
        self.IP_receive_text.setGeometry(QtCore.QRect(70, 450, 181, 31))
        self.IP_receive_text.setObjectName("IP_receive_text")
        self.PORT_receive = QtWidgets.QLabel(self.page_2)
        self.PORT_receive.setGeometry(QtCore.QRect(280, 450, 71, 21))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.PORT_receive.setFont(font)
        self.PORT_receive.setObjectName("PORT_receive")
        self.PORT_receive_text = QtWidgets.QLineEdit(self.page_2)
        self.PORT_receive_text.setGeometry(QtCore.QRect(350, 450, 111, 31))
        self.PORT_receive_text.setObjectName("PORT_receive_text")
        self.receive_play = QtWidgets.QLabel(self.page_2)
        self.receive_play.setGeometry(QtCore.QRect(20, 490, 280, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.receive_play.setFont(font)
        self.receive_play.setText("")
        self.receive_play.setObjectName("receive_play")
        self.receive_widget = QtWidgets.QListWidget(self.page_2)
        self.receive_widget.setGeometry(QtCore.QRect(15, 11, 751, 371))
        self.receive_widget.setStyleSheet("background-color: rgba(170, 255, 127, 120);")
        self.receive_widget.setObjectName("receive_widget")
        self.stackedWidget.addWidget(self.page_2)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)


        self.retranslateUi(MainWindow)
        self.stackedWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "文件安全传输系统"))
        self.send_file.setText(_translate("MainWindow", "发送文件"))
        self.receive_file.setText(_translate("MainWindow", "接收文件"))
        self.current_status.setText(_translate("MainWindow", "当前进度："))
        self.total_status.setText(_translate("MainWindow", "全部进度："))
        self.IP.setText(_translate("MainWindow", "IP:"))
        self.PORT.setText(_translate("MainWindow", "PORT:"))
        self.text_file.setText(_translate("MainWindow", "文件列表:"))
        self.add_file.setText(_translate("MainWindow", "添加"))
        self.delete_file.setText(_translate("MainWindow", "删除"))
        self.empty_file.setText(_translate("MainWindow", "清空"))
        self.handler.setText(_translate("MainWindow", "启动服务器"))
        self.send.setText(_translate("MainWindow", "发送"))
        self.cancel.setText(_translate("MainWindow", "取消"))
        item = self.tableWidget.verticalHeaderItem(0)
        item.setText(_translate("MainWindow", "1"))
        item = self.tableWidget.verticalHeaderItem(1)
        item.setText(_translate("MainWindow", "2"))
        item = self.tableWidget.verticalHeaderItem(2)
        item.setText(_translate("MainWindow", "3"))
        item = self.tableWidget.verticalHeaderItem(3)
        item.setText(_translate("MainWindow", "4"))
        item = self.tableWidget.verticalHeaderItem(4)
        item.setText(_translate("MainWindow", "5"))
        item = self.tableWidget.verticalHeaderItem(5)
        item.setText(_translate("MainWindow", "6"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "文件路径"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "文件大小"))
        self.receive_status.setText(_translate("MainWindow", "当前进度："))
        self.receive.setText(_translate("MainWindow", "准备接收"))
        self.receive_cancel.setText(_translate("MainWindow", "取消"))
        self.IP_receive.setText(_translate("MainWindow", "IP:"))
        self.PORT_receive.setText(_translate("MainWindow", "PORT:"))
        self.status_show.setText(_translate("MainWindow", "状态："))
        #进度条样式
        self.setWindowIcon(QIcon('./数据传输icon.png'))
        self.setStyleSheet('''
            QPushButton {
                border-radius: 15px;         /* 四个角变成圆角 */
            }
            QLineEdit {
                border-radius: 10px;
                font-size: 20px;
            }
            QProgressBar {
                border-radius: 10px;
                text-align: center;
                color: black;
            }
            QProgressBar::chunk {
                background-color: rgb(85, 255, 127);
            }
            QMainWindow {
                background-image: url(./background_image.jpg);  /* 背景图片路径 */
                background-position: center;                    /* 图片居中 */
                background-repeat: no-repeat;                   /* 不重复图片 */
            }
            QTableWidget {
                background-color: rgba(255, 255, 255, 120);  /* 半透明白色 */
                selection-background-color: rgba(0, 120, 215, 120);  /* 半透明选中颜色 */
                border: none;
            }
            QHeaderView::section {
                background-color: rgba(200, 200, 200, 120);  /* 半透明灰色 */
                color: rgba(0, 0, 0, 180);  /* 半透明黑色文字 */
            }
            QTableWidget QScrollBar:horizontal {
                background: rgba(200, 200, 200, 120);
                height: 10px;
            }
            QListWidget {
                border-radius: 20px;
            }
        ''')
