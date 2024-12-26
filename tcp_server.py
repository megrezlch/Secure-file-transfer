from socket import *
import struct
import json
import os
from PyQt5.QtCore import pyqtSignal, QObject
from RSA_Module import *
class TCPServer(QObject):
    #定义信号
    progress_updated = pyqtSignal(int)
    def __init__(self, ip='127.0.0.1', port=8080, buffsize=1024):
        super().__init__()
        self.ip = ip
        self.port = port
        self.buffsize = buffsize
        self.tcp_server = None
        self.command = None
        self.client_conn = False  # 保存客户端连接

    def run_server(self):
        """启动服务器"""
        self.tcp_server = socket(AF_INET, SOCK_STREAM)
        self.tcp_server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.tcp_server.bind((self.ip, self.port))
        self.tcp_server.listen(5)
        generate_rsakey('serverpub.pem', 'serverpri.pem')


    def send_file(self, conn, filename, filesize_bytes, fileindex, ext):
        """发送文件给客户端"""
        newfilename = os.path.basename(filename)
        dirc = {
            'filename': newfilename,
            'filesize_bytes': filesize_bytes,
            'fileindex': fileindex,
            'fileext': ext,
        }
        head_info = json.dumps(dirc)  # 将字典转换成JSON格式
        head_info_len = struct.pack('i', len(head_info))  # 将字符串的长度打包
        # 发送文件信息
        conn.send(head_info_len)  # 发送head_info的长度
        conn.send(head_info.encode('utf-8'))

        # 发送文件数据
        with open(filename, 'rb') as f:
            send_bytes = 0
            while True:
                data = f.read(1024)
                if not data:
                    break
                conn.sendall(data)
                send_bytes += len(data)
                progress = int((send_bytes / filesize_bytes) * 100)
                self.progress_updated.emit(progress)
        self.progress_updated.emit(100)  # 确保进度条达到100%

    def send_serverpub(self, server_conn):
        filesize = os.path.getsize('./.tempfile/serverpub.pem')
        newfilename = 'new_' + os.path.basename('./.tempfile/serverpub.pem')
        dirc = {
            'filename': newfilename,
            'filesize': filesize,
        }
        head_info = json.dumps(dirc)
        head_info_len = struct.pack('i', len(head_info))
        server_conn.send(head_info_len)  # 发送head_info的长度
        server_conn.send(head_info.encode('utf-8'))
        # 发送文件数据
        with open('./.tempfile/serverpub.pem', 'rb') as f:
            data = f.read()
            server_conn.sendall(data)

    def recv_clientpub(self, server_conn):
        head_info_len = server_conn.recv(4)
        head_info_len = struct.unpack('i', head_info_len)[0]

        head_info = server_conn.recv(head_info_len)
        dirc = json.loads(head_info.decode('utf-8'))
        filename = dirc['filename']
        filesize = dirc['filesize']
        received_size = 0
        with open(f'./.tempfile/{filename}', 'wb') as f:
            while received_size < filesize:
                if filesize - received_size > self.buffsize:
                    data = server_conn.recv(self.buffsize)
                    f.write(data)
                    received_size += len(data)
                else:
                    data = server_conn.recv(filesize - received_size)
                    f.write(data)
                    received_size += len(data)
        if received_size == filesize:
            return True, filename
        else:
            return False, filename

    def judge_send_status(self, conn):
        judge_len = conn.recv(4)
        if len(judge_len) == 4:
            judge_len = struct.unpack('i', judge_len)[0]
            judge = conn.recv(judge_len)
            dirc = json.loads(judge.decode('utf-8'))
            if not dirc['state']:
                return False, dirc['fileindex']
            else:
                return True, dirc['fileindex']

