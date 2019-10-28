from bs4 import BeautifulSoup
import requests
import os


LOGIN ="http://127.0.0.1:5000/login"
REGISTER = "http://127.0.0.1:5000/register"

#Test login
# Test wrong username 
r = requests.get(LOGIN)
assert(r.status_code == 200)

data ={
    'uname': 'jac',
    'pword': 'Test@1234',
    '2fa':'0000000000'
}
p = requests.post(url = LOGIN,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="result").text
assert(message =='Incorrect')

#Test wrong 2FA
data ={
    'uname': 'jack',
    'pword': 'Test@1234',
    '2fa':'000000000'
}
p = requests.post(url = LOGIN,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="result").text
assert(message =='Two-factor failure')

#Test username validation
data ={
    'uname': '<script>', #username format not match
    'pword': 'Che@123', 
    '2fa':'00000000000'
}
p = requests.post(url = LOGIN,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="result").text
assert(message =="Username, password or 2FA format doesn't meet the requirement.")

#Test password validation
data ={
    'uname': 'cec',
    'pword': '<script>', #password format not match
    '2fa':'00000000000'
}
p = requests.post(url = LOGIN,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="result").text
assert(message =="Username, password or 2FA format doesn't meet the requirement.")

#Test 2FA validation
data ={
    'uname': 'cec',
    'pword': 'Che@1234',
    '2fa':'<script>' #2FA format not match
}
p = requests.post(url = LOGIN,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="result").text
assert(message =="Username, password or 2FA format doesn't meet the requirement.")


#Test login success
data ={
    'uname': 'Jack',
    'pword': 'Test@1234',
    '2fa':'00000000000' 
}
p = requests.post(url = LOGIN,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="result").text
assert(message =="success")


r = requests.get(REGISTER)
assert(r.status_code == 200)

data ={
    'uname': 'C@>na', #username format not match
    'pword': 'Che@123', 
    '2fa':'00000000000'
}
p = requests.post(url = REGISTER,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="success").text
assert(message =="Username, password or 2FA format doesn't meet the requirement.")


data ={
    'uname': 'cec',
    'pword': 'Che@123', #password format not match
    '2fa':'00000000000'
}
p = requests.post(url = REGISTER,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="success").text
assert(message =="Username, password or 2FA format doesn't meet the requirement.")

data ={
    'uname': 'cec',
    'pword': 'Che@1234',
    '2fa':'000000000' #2FA format not match
}
p = requests.post(url = REGISTER,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="success").text
assert(message =="Username, password or 2FA format doesn't meet the requirement.")

#Username, password and 2FA format meet requirement
data ={
    'uname': 'test1',
    'pword': 'Test@1234',
    '2fa':'00000000000' 
}
p = requests.post(url = REGISTER,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="success").text
assert(message =="success")

#Existed user, return failure
data ={
    'uname': 'test1',
    'pword': 'Test@1234',
    '2fa':'00000000000' 
}
p = requests.post(url = REGISTER,data=data)
soup = BeautifulSoup(p.text,'html.parser')
message = soup.find(id="success").text
assert(message =="failure")

#Reset user.txt


print("All tests using bs4 are completed")