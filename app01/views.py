from django.shortcuts import render,HttpResponse,redirect
from geetest import GeetestLib
from django.contrib import auth
from django.http import JsonResponse
from django import forms
from django.forms import widgets
from app01 import models
from django.core.exceptions import ValidationError
from django.db.models import Count
# 用户登录
def login(request):
    # if request.is_ajax():  # 如果是AJAX请求
    if request.method == "POST":
        # 初始化一个给AJAX返回的数据
        ret = {"status": 0, "msg": ""}
        # 从提交过来的数据中 取到用户名和密码
        username = request.POST.get("username")
        pwd = request.POST.get("password")
        # 获取极验 滑动验证码相关的参数
        gt = GeetestLib(pc_geetest_id, pc_geetest_key)
        challenge = request.POST.get(gt.FN_CHALLENGE, '')
        validate = request.POST.get(gt.FN_VALIDATE, '')
        seccode = request.POST.get(gt.FN_SECCODE, '')
        status = request.session[gt.GT_STATUS_SESSION_KEY]
        user_id = request.session["user_id"]

        if status:
            result = gt.success_validate(challenge, validate, seccode, user_id)
        else:
            result = gt.failback_validate(challenge, validate, seccode)
        if result:
            # 验证码正确
            # 利用auth模块做用户名和密码的校验
            user = auth.authenticate(username=username, password=pwd)
            if user:
                # 用户名密码正确
                # 给用户做登录
                auth.login(request, user)
                ret["msg"] = "/index/"
            else:
                # 用户名密码错误
                ret["status"] = 1
                ret["msg"] = "用户名或密码错误！"
        else:
            ret["status"] = 1
            ret["msg"] = "验证码错误"

        return JsonResponse(ret)
    return render(request, "login2.html")


#用户注销
def logout(request):
    auth.logout(request)
    return redirect('/index/')

#用户页面
def index(request):
    article_list=models.Article.objects.all()
    return render(request, "index.html",{'article_list':article_list})

# 请在官网申请ID使用，示例ID不可使用
pc_geetest_id = "b46d1900d0a894591916ea94ea91bd2c"
pc_geetest_key = "36fc3fe98530eea08dfc6ce76e3d24c4"


# 处理极验 获取验证码的视图
def get_geetest(request):
    user_id = 'test'
    gt = GeetestLib(pc_geetest_id, pc_geetest_key)
    status = gt.pre_process(user_id)
    request.session[gt.GT_STATUS_SESSION_KEY] = status
    request.session["user_id"] = user_id
    response_str = gt.get_response_str()
    return HttpResponse(response_str)

#forms组件
class RegForm(forms.Form):
    username = forms.CharField(
        label='用户名',
        max_length=16,
        widget=widgets.TextInput(attrs={'class':'form-control'}),
        error_messages={
            'required':'不能为空',
        }
    )
    password = forms.CharField(
        label='密码',
        min_length=6,
        widget=widgets.PasswordInput(attrs={'class': 'form-control'}),
        error_messages={
            'required':'不能为空',
            'invalid': '格式错误',
            'min_length': '密码最短为6位'
        }
    )
    rel_password = forms.CharField(
        label='密码',
        min_length=6,
        widget=widgets.PasswordInput(attrs={'class': 'form-control'}),
        error_messages={
            'required':'不能为空',
            'invalid': '格式错误',
            'min_length': '密码最短为6位'
        }
    )
    email = forms.EmailField(
        label='邮箱',
        widget=widgets.EmailInput(attrs={'class': 'form-control'}),
        error_messages={
            'required':'不能为空',
            'invalid': '格式错误',
        }
    )
    def clean(self):
        password = self.cleaned_data.get('password')
        rel_password = self.cleaned_data.get("rel_password")
        if rel_password and password != rel_password:
            self.add_error("rel_password",ValidationError('两次密码不一致'))
        else:
            return self.cleaned_data
    def clean_username(self):
        username = self.cleaned_data.get('username')
        rep = models.UserInfo.objects.filter(username=username)
        if rep:
            self.add_error("username",ValidationError('此用户已被注册'))
        else:
            return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        rep = models.UserInfo.objects.filter(email=email)
        if rep:
            self.add_error("email", ValidationError('此邮箱已被注册'))
        else:
            return email

#注册用户
def sign(request):
    form_obj = RegForm()
    if request.method == 'POST':
        ret={'status':0,'msg':''}
        form_obj = RegForm(request.POST)
        if form_obj.is_valid():
            form_obj.cleaned_data.pop("rel_password")
            avatar_img = request.FILES.get('avatar')
            models.UserInfo.objects.create_user(**form_obj.cleaned_data,avatar=avatar_img)
            ret['msg']='/index/'
            return JsonResponse(ret)
        else:
            ret['status']=1
            ret['msg']=form_obj.errors
            return JsonResponse(ret)
    return render(request,'sign.html',{'form_obj':form_obj})


#ajax检验用户名是否注册过
def check_username(request):
    ret = {'static':0,'msg':''}
    username = request.GET.get('username')
    rep = models.UserInfo.objects.filter(username=username)
    if rep:
        ret['status']=1
        ret['msg']='此用户已被注册'
    return JsonResponse(ret)


#个人博客主页

def home(request,username):
    user = models.UserInfo.objects.filter(username=username).first()
    if not user:
        return HttpResponse('404')
    blog = user.blog
    article_list = models.Article.objects.filter(user=user)
    category_list = models.Category.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    tag_list = models.Tag.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    archive_list = models.Article.objects.filter(user=user).extra(
        select={"archive_ym": "date_format(create_time,'%%Y-%%m')"}
    ).values("archive_ym").annotate(c=Count("nid")).values("archive_ym", "c")
    return render(request,
                  'home.html',
                  {
                      "blog":blog,
                      "username":username,
                      "article_list":article_list,
                      "category_list":category_list,
                      'tag_list':tag_list,
                      "archive_list":archive_list
                  }
                  )


#文章详细页面
def article_detail(request, username, pk):
    user = models.UserInfo.objects.filter(username=username).first()
    if not user:
        return HttpResponse('404')
    blog = user.blog
    comment_list = models.Comment.objects.filter(article_id=pk)
    article_obj = models.Article.objects.filter(pk=pk).first()
    article_list = models.Article.objects.filter(user=user)
    category_list = models.Category.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    tag_list = models.Tag.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    archive_list = models.Article.objects.filter(user=user).extra(
        select={"archive_ym": "date_format(create_time,'%%Y-%%m')"}
    ).values("archive_ym").annotate(c=Count("nid")).values("archive_ym", "c")
    return render(request,
                  'article_detail.html',
                  {
                      "blog": blog,
                      "username": username,
                      "article_list": article_list,
                      "category_list": category_list,
                      'tag_list': tag_list,
                      "archive_list": archive_list,
                      "article":article_obj ,
                      "comment_list":comment_list,
                  }
                  )


#文章标签列表详细内容

def article_tags(request,username,title):
    user = models.UserInfo.objects.filter(username=username).first()
    if not user:
        return HttpResponse('404')
    blog = user.blog
    article_tag_obj = models.Tag.objects.filter(title=title)
    ret = models.Tag.objects.get(title=title)
    print(ret)
    article_list = models.Article.objects.filter(tags=ret.nid)
    print(article_list)
    category_list = models.Category.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    tag_list = models.Tag.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    archive_list = models.Article.objects.filter(user=user).extra(
        select={"archive_ym": "date_format(create_time,'%%Y-%%m')"}
    ).values("archive_ym").annotate(c=Count("nid")).values("archive_ym", "c")
    return render(request,
                  'article_tags.html',
                  {
                      "blog": blog,
                      "username": username,
                      "article_list": article_list,
                      "category_list": category_list,
                      'tag_list': tag_list,
                      "archive_list": archive_list,
                      "tags":article_tag_obj,
                  }
                  )


#文章分类详情列表页
def article_category(request,username,title):
    user = models.UserInfo.objects.filter(username=username).first()
    if not user:
        return HttpResponse('404')
    blog = user.blog
    article_category_list= models.Category.objects.filter(title=title)
    ret = models.Category.objects.get(title=title)
    print(ret)
    article_list = models.Article.objects.filter(category=ret.nid)
    print(article_list)
    category_list = models.Category.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    tag_list = models.Tag.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    archive_list = models.Article.objects.filter(user=user).extra(
        select={"archive_ym": "date_format(create_time,'%%Y-%%m')"}
    ).values("archive_ym").annotate(c=Count("nid")).values("archive_ym", "c")
    return render(request,
                  'article_category.html',
                  {
                      "blog": blog,
                      "username": username,
                      "article_list": article_list,
                      "category_list": category_list,
                      'tag_list': tag_list,
                      "archive_list": archive_list,
                      "categorys":article_category_list,
                  }
                  )


#日期归档详情页
def article_archive(request,username,date):
    user = models.UserInfo.objects.filter(username=username).first()
    if not user:
        print('*'*120)
        return HttpResponse('404')
    blog = user.blog
    category_list = models.Category.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    tag_list = models.Tag.objects.filter(blog=blog).annotate(c=Count("article")).values("title", "c")
    archive_list = models.Article.objects.filter(user=user).extra(
        select={"archive_ym": "date_format(create_time,'%%Y-%%m')"}
    ).values("archive_ym").annotate(c=Count("nid")).values("archive_ym", "c")
    year,month = date.split('-')
    print(year,month)  #其中month是01，02时会发生错误
    article_list = models.Article.objects.filter(user=user).filter(
        create_time__year=year,create_time__month=month
    )
    print(article_list)
    return render(request,
                  'article_archive.html',
                  {
                      "blog": blog,
                      "username": username,
                      # "article_list": article_list,
                      "category_list": category_list,
                      'tag_list': tag_list,
                      "archive":date,
                      'archive_list':archive_list,
                  }
                  )


import json
from django.db.models import F


def up_down(request):
    ret={'status': 1, 'msg': ''}
    user = request.user
    article_id = request.POST.get('article_id')
    is_up = json.loads(request.POST.get('is_up'))
    try:
        models.ArticleUpDown.objects.create(is_up=is_up,article_id=article_id,user=user)
        models.Article.objects.filter(pk=article_id).update(up_count=F("up_count") + 1)
    except Exception as e:
        ret['status']=0
        ret['msg'] = models.ArticleUpDown.objects.filter(user=user,article_id=article_id).first().is_up
    return JsonResponse(ret)


def comment(request):
    ret={}
    pid = request.POST.get('pid')
    article_id = request.POST.get('article_id')
    content = request.POST.get('content')
    user_pk = request.user.pk
    if not pid:
        comment_obj = models.Comment.objects.create(article_id=article_id,user_id=user_pk,content=content)
    else:
        comment_obj = models.Comment.objects.create(article_id=article_id, user_id=user_pk, content=content,parent_comment_id=pid)
    ret['create_time']=comment_obj.create_time.strftime('%Y-%m-%d')
    ret['content']=comment_obj.content
    ret['username']=comment_obj.user.username
    return JsonResponse(ret)




