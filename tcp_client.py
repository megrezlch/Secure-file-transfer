from socket import *
import struct
import json
from RSA_Module import *
from Zip_Module import *
from AES import AESdecrypt
from PyQt5.QtCore import pyqtSignal, QObject

class TCPClient(QObject):
    # 定义自定义信号

    list_received = pyqtSignal(str)
    receive_status = pyqtSignal(str)  # 当发生错误时发出或者一些状态文件
    receive_progress = pyqtSignal(int)
    def __init__(self,  buffsize=1024):
        super().__init__()
        self.buffsize = buffsize
        self.tcp_client = socket(AF_INET, SOCK_STREAM)
        self.connected = False
    def connect(self, ip, port):
        self.tcp_client.connect_ex((ip, port))
        self.connected = True
        generate_rsakey('clientpub.pem', 'clientpri.pem')
        return self.tcp_client
    def send_clientpub(self, client_conn):
        filesize = os.path.getsize('./.tempfile/clientpub.pem')
        newfilename = 'new_' + os.path.basename('./.tempfile/clientpub.pem')
        dirc = {
            'filename': newfilename,
            'filesize': filesize,
        }
        head_info = json.dumps(dirc)
        head_info_len = struct.pack('i', len(head_info))
        client_conn.send(head_info_len)#发送head_info的长度
        client_conn.send(head_info.encode('utf-8'))

        #发送文件数据
        with open('./.tempfile/clientpub.pem', 'rb') as f:
            data = f.read()
            client_conn.sendall(data)


    def recv_serverpub(self, client_conn):
        head_info_len = client_conn.recv(4)
        head_info_len = struct.unpack('i',head_info_len)[0]

        #接收并解析报头内容
        head_info = client_conn.recv(head_info_len)
        dirc = json.loads(head_info.decode('utf-8'))
        filename = dirc['filename']
        filesize = dirc['filesize']
        received_size = 0
        with open(f'./.tempfile/{filename}', 'wb') as f:
            while received_size < filesize:
                if filesize - received_size > self.buffsize:
                    data = client_conn.recv(self.buffsize)
                    f.write(data)
                    received_size += len(data)
                else:
                    data = client_conn.recv(filesize - received_size)
                    f.write(data)
                    received_size += len(data)
        if received_size == filesize:
            return True, filename
        else:
            return False, filename

    def receive(self, client_conn):
        if not client_conn:
            self.receive_status.emit("未连接到服务端")
            return
        try:
            i = 1
            while True:
                head_info_len = client_conn.recv(4)
                if head_info_len == 4:
                    self.receive_status.emit('正在接收文件中...')
                head_info_len = struct.unpack('i', head_info_len)[0]

                # 接收并解析报头内容
                head_info = client_conn.recv(head_info_len)
                dirc = json.loads(head_info.decode('utf-8'))
                filename = dirc['filename']
                filesize_bytes = dirc['filesize_bytes']
                fileindex = dirc['fileindex']
                ext = dirc['fileext']
                lineEdit1 = '正在接收第' + str(i) + \
                           '号文件【' + filename + '】......'
                self.list_received.emit(lineEdit1)
                received_size = 0
                with open(f'./.tempfile/{filename}', 'wb') as f:
                    while received_size < filesize_bytes:
                        if filesize_bytes - received_size > self.buffsize:
                            data = client_conn.recv(self.buffsize)
                            f.write(data)
                            received_size += len(data)
                        else:
                            data = client_conn.recv(filesize_bytes - received_size)
                            f.write(data)
                            received_size += len(data)
                        self.receive_progress.emit(int((received_size / filesize_bytes) * 100))
                lineEdit2 = '成功接收第' + str(i) + \
                           '号文件【' + filename + '】 --> ' + \
                           os.getcwd() + '\\.tempfile\\' + filename
                self.list_received.emit(lineEdit2)
                if not self.sign_file(filename, ext):   #发送签名状态
                    self.send_state(client_conn, i, False)
                    self.list_received.emit(f'第{i}号文件签名错误，重新接收...')
                else:
                    self.send_state(client_conn, i, True)
                    self.list_received.emit(f'第{i}号文件签名验证成功')
                    i = i + 1
                if fileindex == -1:
                    self.receive_status.emit('文件全部安全接收完成')
                    break

        except Exception as e:
            print(f'接收文件失败: {e}')
        return
    def sign_file(self, filename, ext):
        unzip_file(f'./.tempfile/{filename}', './.tempfile')
        aeskey = RSAdecrypt('./.tempfile/clientpri.pem', f'./.tempfile/{filename}_key')
        decrypted_message = AESdecrypt(f'./.tempfile/{filename}{ext}', aeskey)
        state = verify_signature(decrypted_message,'./.tempfile/new_serverpub.pem',f'./.tempfile/{filename}_sig')
        if state:
            with open(f'./.tempfile/{filename}{ext}', 'rb') as f :
                data = f.read()
                with open(f'./{filename}{ext}', 'wb') as s:
                    s.write(data)

        return state
    def send_state(self,client_conn, fileindex, state):
        dirc = {
            'fileindex': fileindex,
            'state': state,
        }
        head_info = json.dumps(dirc)
        head_info_len = struct.pack('i', len(head_info))

        client_conn.send(head_info_len)  # 发送head_info的长度
        client_conn.send(head_info.encode('utf-8'))




