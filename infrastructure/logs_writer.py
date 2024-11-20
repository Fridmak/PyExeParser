from infrastructure.constants import LOGS_FILE
def write_log(text):
    with open(LOGS_FILE, 'a') as f:
        f.write(text + '\n')

def clear_logs():
    with open(LOGS_FILE, 'w') as f:
        pass
