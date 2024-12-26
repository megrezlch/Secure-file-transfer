import sys
from PyQt5.QtWidgets import QApplication, QMainWindow,  QTableWidgetItem, QFileDialog
from PyQt5 import QtWidgets
from newfile import Ui_MainWindow # 导入生成的UI类
from tcp_client import TCPClient
from tcp_server import TCPServer
from isIP import isIP,isPORT
from AES import *
from RSA_Module import *
from Zip_Module import *
import os
import threading
import time
import shutil

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # 设置UI
        #初始化TCP服务器
        self.client_conn = None
        self.running = True
        self.run_client = True
        self.server =TCPServer()
        self.conn =None
        self.client = TCPClient()
        self.client_conn = None
        #client文件信号
        # self.client_recv = TCPClient_recv()
        self.client.receive_status.connect(self.add_list)
        self.client.list_received.connect(self.add_list)
        self.client.receive_progress.connect(self.update_receive_bar)

        #连接按钮点击事件自动跳转到自定义槽函数
        self.send_file.clicked.connect(self.show_send_page)
        self.receive_file.clicked.connect(self.show_receive_page)
        self.add_file.clicked.connect(self.read_file)
        self.handler.clicked.connect(self.toggle_server)
        self.receive.clicked.connect(self.toggle_client)
        self.send.clicked.connect(self.send_files)
        self.delete_file.clicked.connect(self.delete_filex)
        self.empty_file.clicked.connect(self.delete_all_filex)
        self.server.progress_updated.connect(self.update_current_bar)


    def mk_temp_files(self):
        """创建临时文件夹"""
        temp_dir = './.tempfile'
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

    def del_temp_files(self):
        """删除临时文件夹及其内容"""
        temp_dir = './.tempfile'
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                print(f"Temporary directory deleted: {temp_dir}")
            except Exception as e:
                print(f"Failed to delete temporary directory: {e}")
    def closeEvent(self, event):
        """重写 closeEvent 方法，在窗口关闭时删除临时目录"""
        self.del_temp_files()
        # 调用父类的 closeEvent 方法，确保窗口正常关闭
        super().closeEvent(event)

#-------------------------------------------------------------------------------------------------
    #左上角三个按钮
    #读文件
    def read_file(self):
        filename, _ =QFileDialog.getOpenFileName(self, "选取文件", "C:/", "All Files(*)")
        if not filename:
            return  #如果用户取消选择=文件，直接返回
        # 获取文件的字节大小
        file_size_bytes = os.path.getsize(filename)
        file_size_str = f"{file_size_bytes}字节"
        # 找到当前表格的最后一行（非空行）
        row_count = self.tableWidget.rowCount()
        for row in range(row_count):
            item = self.tableWidget.item(row, 0)
            if not item or item.text().strip() == "":  # 检查第一列是否为空或仅包含空白字符
                break
        else:
            # 如果所有行都已填满，增加新行
            self.tableWidget.insertRow(row_count)
            row = row_count
        self.tableWidget.setItem(row, 0, QTableWidgetItem(filename))
        self.tableWidget.setItem(row, 1, QTableWidgetItem(file_size_str))
    #删除文件
    def delete_filex(self):
        row_count = self.tableWidget.rowCount()
        if row_count > 0:
            for row in range(row_count):
                item = self.tableWidget.item(row, 0)
                if not item or item.text().strip() == "":  # 检查第一列是否为空或仅包含空白字符
                    break
            self.tableWidget.setItem(row-1, 0, QTableWidgetItem(""))
            self.tableWidget.setItem(row-1, 1, QTableWidgetItem(""))
        else:
            return
    #删除全部文件
    def delete_all_filex(self):
        self.tableWidget.clearContents()

    def read_table(self):
        row_count = self.tableWidget.rowCount()
        filenames = []
        filesizes = []
        newfilenames = []
        newfilesizes = []
        exts = []
        for row in range(row_count):
            filename_item = self.tableWidget.item(row, 0)
            filetype_item = self.tableWidget.item(row, 1)

            if filename_item is not None:
                filenames.append(filename_item.text())

            if filetype_item is not None:
                filesizex = int(filetype_item.text().strip('字节'))
                filesizes.append(filesizex)
        for i in range(len(filenames)):
            basename, ext = os.path.splitext(os.path.basename(filenames[i])) #不带扩展名的文件
            aeskey = create_key(basename)    #生成对称密钥
            sign_message(filenames[i], './.tempfile/serverpri.pem', f'./.tempfile/{basename}_sig') #计算摘要加签名

            with open(filenames[i],'rb') as f:  #使用对称密钥对文件进行加密
                data = f.read()
                with open(f'./.tempfile/{basename}{ext}', 'wb') as s:
                    endata = AESencrypt(data, aeskey)
                    s.write(endata)
            RSAencrypt('./.tempfile/new_clientpub.pem', aeskey, f'./.tempfile/{basename}_key')#对对称密钥进行加密
            files_to_zip = [
                f'./.tempfile/{basename}_sig',
                f'./.tempfile/{basename}{ext}',
                f'./.tempfile/{basename}_key'
            ]
            zip_filename = f'./.tempfile/{basename}'
            zip_files(zip_filename, files_to_zip)
            newfilenames.append(zip_filename)
            #获取文件大小
            file_size_bytes = os.path.getsize(zip_filename)
            newfilesizes.append(file_size_bytes)
            #文件后缀
            exts.append(ext)



        return newfilenames,newfilesizes,exts
#----------------------------------------------------------------------------------
    #服务端
    def send_files(self):
        filenames, filesizes, exts = self.read_table()
        self.send_fileth(filenames, filesizes, exts)
    def send_fileth(self, filenames, filesizes, exts):
        if not self.conn:
            self.update_status(f'服务器未连接')
            return
        self.thread_send = threading.Thread(target=self.send_file_all, kwargs={'filenames': filenames, 'filesizes': filesizes, 'exts': exts})
        self.thread_send.start()

    def send_file_all(self, filenames, filesizes, exts):
        send_file = 0
        i = 0
        while i < len(filenames):
            self.update_status(f"{filenames[i]}文件发送中")
            if i + 1 == len(filenames):
                index = -1
            else:
                index = i + 1
            self.server.send_file(self.conn, filenames[i], filesizes[i], index, exts[i])
            send_file += 1
            state, fileindex = self.server.judge_send_status(self.conn)
            i = i + 1
            progress = int((send_file / len(filenames)) * 100)
            self.update_total_bar(progress)
            if not state:
                i = fileindex - 1
                self.update_status(f'{filenames[fileindex]}传输错误，重传中...')
                time.sleep(3)

        self.update_status(f"文件全部发送完成")
        self.server.wait_for_send = False


    def toggle_server(self):
        if self.running:
            self.thread = threading.Thread(target=self.start_server)
            self.thread.start()
        else:
            self.running = True
            if self.thread and self.thread.is_alive():
                self.thread.join()
            self.handler.setText('启动服务器')

    def start_server(self):
        ip_address = self.IP_text.text().strip()  # 读取并去除可能存在的空白字符
        port = self.PORT_text.text().strip()
        if not (isIP(ip_address) and isPORT(port)):
            # 如果不是有效的 IP 地址
            self.update_status('ip is error.')
            return
        self.handler.setText('停止服务器')
        self.running = False
        self.update_status(f'等待客户端连接...')
        self.server.ip = ip_address
        self.server.port = int(port)

        self.server.run_server()
        conn, addr = self.server.tcp_server.accept()
        self.conn = conn  # 保存客户端连接
        if conn:
            # self.server.client_conn = True
            self.update_status(f'客户端连接成功')
        else:
            self.update_status(f'客户端连接失败')
        state, pubname = self.server.recv_clientpub(self.conn)
        if state:
            self.update_status(f'{pubname}接收成功')
        else:
            self.update_status(f'{pubname}接收失败')
        self.server.send_serverpub(self.conn)


#--------------------------------------------------------------------------------
    #客户端

    def toggle_client(self):
        if self.run_client:
            self.thread_client = threading.Thread(target=self.start_client)
            self.thread_client.start()
        else:
            self.run_client = True
            if self.thread_client and self.thread_client.is_alive():
                self.thread_client.join()
            self.receive.setText('接收')
    def start_client(self):
        ip = self.IP_receive_text.text().strip()  # 读取并去除可能存在的空白字符
        port = self.PORT_receive_text.text().strip()

        if not (isIP(ip) and isPORT(port)):
            # 如果不是有效的 IP 地址
            self.update_receive_play('ip or port is error.')
            return
        port = int(port)
        self.receive.setText('接收中')
        self.run_client = False
        self.update_receive_play(f'服务端连接中')
        time.sleep(2)
        self.client_conn = self.client.connect(ip, port)
        if self.client_conn:
            self.receive.setEnabled(False)
            self.update_receive_play(f'连接服务端成功')
        else:
            self.update_receive_play(f'连接服务端失败')
            return
        self.client.send_clientpub(self.client_conn)
        state, pubname = self.client.recv_serverpub(self.client_conn)
        if state:
            self.update_receive_play(f'{pubname}接收成功')
        else:
            self.update_receive_play(f'{pubname}接收失败')
        self.client.receive(self.client_conn)
        self.receive.setEnabled(True)







#--------------------------------------------------------------------------------
    #更新显示常用函数。
    def update_current_bar(self, value):
        self.current_status_bar.setValue(value)

    def update_total_bar(self, value):
        self.total_status_bar.setValue(value)

    def update_receive_bar(self, value):
        self.receive_bar.setValue(value)

    def add_list(self, text):
        if text:
            item = QtWidgets.QListWidgetItem(text)  # 创建一个新的 QListWidgetItem
            self.receive_widget.addItem(item)  # 将新项目添加到 QListWidget
            self.receive_widget.scrollToItem(item)  # 滚动到最新添加的项目

    def update_status(self, message):
        self.status_show.setText(message)
    def update_receive_play(self, message):
        self.receive_play.setText(message)
    def show_send_page(self):
        """切换到发送文件页面"""
        self.stackedWidget.setCurrentIndex(0)

    def show_receive_page(self):
        """切换到接收文件页面"""
        self.stackedWidget.setCurrentIndex(1)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()  # 显示窗口
    window.mk_temp_files()
    sys.exit(app.exec_())


