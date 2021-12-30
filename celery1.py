from celery import Celery
from time import sleep

app = Celery('hello', broker='amqp://guest@localhost//')

@app.task
def hello():
    sleep(10)
    return 'hello world'