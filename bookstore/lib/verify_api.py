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


def send_email(email, requestPool):
    pass


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
