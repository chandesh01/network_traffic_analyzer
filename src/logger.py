class Logger:
    def __init__(self, filename="capture.log"):
        self.file = open(filename, "a", encoding="utf-8")

    def log(self, text):
        self.file.write(text + "\n")
        self.file.flush()