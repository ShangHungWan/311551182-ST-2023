from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager

driver = webdriver.Chrome(service=ChromeService(
    ChromeDriverManager().install()))

driver.get('https://www.nycu.edu.tw')

driver.maximize_window()

newsAEle = driver.find_element(
    By.XPATH, '/html/body/div[1]/div/main/div/div/div/article/div/div/div/div/section[2]/div/div/div[1]/div/div/div/div/nav[1]/ul/li[2]/a')
newsAEle.click()

firstArticleEle = driver.find_element(
    By.XPATH, '/html/body/div[1]/div/main/div[1]/div/div/article/div/div/div/div/section/div/div/div/div/div/div[3]/div/div/div[2]/div[1]/ul/li[1]/a')
firstArticleEle.click()

titleEle = driver.find_element(
    By.XPATH, '/html/body/div[1]/div/main/div/div/div/article/header/h1')
contentEle = driver.find_element(
    By.XPATH, '/html/body/div[1]/div/main/div/div/div/article/div')
print(titleEle.text)
print(contentEle.text)

driver.switch_to.new_window('tab')

driver.get('https://www.google.com')
inputEle = driver.find_element(
    By.XPATH, '/html/body/div[1]/div[3]/form/div[1]/div[1]/div[1]/div/div[2]/input')
inputEle.send_keys('311551182')
inputEle.send_keys(Keys.ENTER)

secondResultEle = driver.find_element(
    By.XPATH, '/html/body/div[7]/div/div[11]/div/div[2]/div[2]/div/div/div[2]/div/div/div[1]/div/a/h3')
print(secondResultEle.text)

driver.quit()
