import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import Select
from selenium.webdriver import ActionChains

options = Options()
options.add_argument("--headless")
options.add_argument("--window-size=1920,1080")
options.add_argument("--disable-gpu")
driver = webdriver.Chrome(
    service=ChromeService(ChromeDriverManager().install()), options=options
)

driver.maximize_window()
driver.get("https://docs.python.org/3/tutorial/index.html")

WebDriverWait(driver, 3).until(
    EC.presence_of_element_located(
        (By.CSS_SELECTOR, '#language_select>option[value=zh-tw]')
    )
)

headerEle = WebDriverWait(driver, 3).until(
    EC.presence_of_element_located(
        (By.CSS_SELECTOR, "#the-python-tutorial > h1:nth-child(2)"))
)
firstParagraphEle = WebDriverWait(driver, 3).until(
    EC.presence_of_element_located(
        (By.CSS_SELECTOR, "#the-python-tutorial > p:nth-child(3)"))
)

print(headerEle.text)
print(firstParagraphEle.text)

searchBarEle = driver.find_element(
    By.CSS_SELECTOR, 'div.related:nth-child(2) > ul:nth-child(2) > li:nth-child(11) > div:nth-child(1) > form:nth-child(1) > input:nth-child(1)')
searchBarEle.send_keys("class")
searchBarEle.send_keys(Keys.ENTER)

searchResultEle = WebDriverWait(driver, 5).until(
    EC.presence_of_element_located(
        (By.CSS_SELECTOR, ".search > li:nth-child(5) > a:nth-child(1)"))
)
resultsEles = driver.find_elements(
    By.CSS_SELECTOR, ".search > li > a")

print()
count = 0
for i in resultsEles:
    count += 1
    if (count > 5):
        break
    print(i.text)

driver.quit()
