def write_log(text):
    with open('../log.txt', 'a') as f:
        f.write(text + '\n')

def clear_logs():
    with open('../log.txt', 'w') as f:
        pass
