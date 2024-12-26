import zipfile
import os

    

def unzip_file(zip_filename = 'output.zip',destination_directory = './temp'):
    """
    解压指定的ZIP文件到目标目录

    :param zip_filename: 要解压的ZIP文件的路径。
    :param destination_directory: 解压后的文件存放的目标目录。
    """
    try:
        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            # 检查ZIP文件是否损坏
            bad_file = zip_ref.testzip()
            if bad_file is not None:
                print(f"Error:到达的文件 {bad_file} 在ZIP存档中损坏。")
                return

            print(f"正在将文件 {zip_filename} 解压到 {destination_directory}")
            zip_ref.extractall(destination_directory)
            print("解压完成")
            
    except zipfile.BadZipFile:
        print(f"Error: 文件 {zip_filename} 不是一个有效的ZIP文件。")
    except Exception as e:
        print(f"发生了一个错误: {e}")


def zip_files(zip_filename, files_to_compress):
    """
    files_to_compress = [
        './.tempfile/file1.txt',
        './.tempfile/file2.txt',
        './.tempfile/file3.txt'
    ]
    zip_filename = './.tempfile/compressed_files.zip'
    """
    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files_to_compress:
                if os.path.isfile(file):
                    # 构建文件在 ZIP 文件中的名称（使用相对路径）
                    arcname = os.path.basename(file)  # 只保留文件名
                    # 将文件添加到 ZIP 文件中
                    zipf.write(file, arcname)
                    print(f"文件{file}已添加到压缩文件中")
    except Exception as e:
        print(f"发生压缩错误: {e}")