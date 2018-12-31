import json
'''
    本文件存储了用于验证码
'''
# 验证码生成和验证所需的接口和参数
api_link = 'http://hb9.api.okayapi.com/'
ver_create = 'App.Captcha.Create'
ver_verify = 'App.Captcha.Verify'
mail_send = 'App.Email.Send'
app_key = '3BD85315E2B9E10DA18E32653F5CD2D4'
email_send = 'App.Email.Send'
message = \
            """
                    %s正在要求重置密码，如果确认操作的是您本人，请点击<a href = %s>这儿</a>进行密码重置操作；
                    如果不是，请确保别人不会在一定时间内获取到这份邮件；不用担心，您的账户暂时是安全的；如果您
                    并没有在本网站上注册账号，请忽略这份邮件。谢谢！
            """


def send_email(request_pool, email, link_addr):
    global app_key
    global api_link
    global email_send
    global message
    fields = {
        's': email_send,
        'app_key': app_key,
        'address': email,
        'title': "重置密码——阳光书屋",
        'content': (message % (email, link_addr))
    }
    request = request_pool.request("POST", api_link, fields=fields)
    if request.status != 200:
        return False
    else:
        return True


def get_verify_code(http_pool):
    global app_key
    global api_link
    global ver_create
    para = {
        's': ver_create,
        'app_key': app_key,
        'return_format': 'data',
    }
    req = http_pool.request("POST", api_link, fields=para)
    if req.status != 200:
        return None
    else:
        return req.data


def verify_code(http_pool, c_id, c_code):
    global app_key
    global api_link
    para = {
        'app_key': app_key,
        'captcha_id': c_id,
        'captcha_code': c_code,
        's': ver_verify
    }
    req = http_pool.request("POST", api_link, fields=para)
    if req.status != 200:
        return None
    else:
        return req.data
