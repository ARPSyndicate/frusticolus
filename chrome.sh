mkdir chrome
cd chrome
sudo rm -r /var/chrome
sudo mkdir /var/chrome

wget https://storage.googleapis.com/chrome-for-testing-public/125.0.6422.78/linux64/chrome-linux64.zip
unzip chrome-linux64.zip 
sudo mv chrome-linux64/* /var/chrome/

wget https://storage.googleapis.com/chrome-for-testing-public/125.0.6422.78/linux64/chromedriver-linux64.zip
unzip chromedriver-linux64.zip
sudo mv chromedriver-linux64/chromedriver /usr/bin/chromedriver
sudo chmod +x /usr/bin/chromedriver

cd ..
rm -r chrome