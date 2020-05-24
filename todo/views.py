from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.db import IntegrityError
from django.contrib.auth import login, authenticate, logout
from .forms import Todoform
from .models import Todo
from django.utils import timezone
from django.contrib.auth.decorators import login_required


def signupUser(request):
    if request.method == 'GET':
        return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(username=request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('home')
            except IntegrityError:
                messages.info(request, 'Username already taken. Please choose different Username.')
                return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})
        else:
            messages.info(request, 'Password done not match')
            return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})


def home(request):
    return render(request, 'todo/home.html')


@login_required(login_url='/login/')
def logoutUser(request):
    logout(request)
    return redirect('home')


def loginUser(request):
    if request.method == 'GET':
        return render(request, 'todo/loginuser.html', {'form': AuthenticationForm})
    else:
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return render(request, 'todo/home.html')
        else:
            messages.info(request, 'Username or Password Wrong!')
            return render(request, 'todo/loginuser.html',{'form': AuthenticationForm})


@login_required(login_url='/login/')
def createtodos(request):
    if request.method == 'GET':
        return render(request, 'todo/createtodo.html', {'form': Todoform()})
    else:
        try:
            form = Todoform(request.POST)
            newtodo = form.save(commit=False)
            newtodo.userId = request.user
            newtodo.save()
            return redirect('currenttodos')
        except ValueError:
            messages.info(request, 'Bad data passed in.Try Again')
            return render(request, 'todo/createtodo.html', {'form': Todoform()})


@login_required(login_url='/login/')
def currenttodos(request):
    todos = Todo.objects.filter(userId=request.user, datecomplated__isnull=True)
    return render(request, 'todo/currenttodos.html', {'todos': todos})


@login_required(login_url='/login/')
def viewtodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, userId=request.user)

    if request.method == 'GET':
        form = Todoform(instance=todo)
        return render(request, 'todo/viewtodo.html', {'todo': todo, 'form': form})
    else:
        try:
            form = Todoform(request.POST, instance=todo)
            form.save()
            return redirect('currenttodos')
        except ValueError:
            messages.info(request, 'Bad data passed in.Try Again')
            return render(request, 'todo/createtodo.html', {'form': Todoform()})


@login_required(login_url='/login/')
def complatetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, userId=request.user)
    if request.method == 'POST':
        todo.datecomplated = timezone.now()
        todo.save()
        return redirect('currenttodos')


@login_required(login_url='/login/')
def deletetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, userId=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('currenttodos')


@login_required(login_url='/login/')
def completedtodos(request):
    todos = Todo.objects.filter(userId=request.user, datecomplated__isnull=False).order_by('-datecomplated')
    return render(request, 'todo/completedtodos.html', {'todos': todos})
