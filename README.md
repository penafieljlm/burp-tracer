# Burp Tracer
This is a simple extension for Burp Suite which takes your current site map, extracts each request parameter, and searches for responses where its value is present. This tool was developed with output validation testing (e.g. XSS) in mind.

The tool respects the scope that you indicated in the "Scope" tab of the "Target" module.

![Alt text](/docs/screenshot.png?raw=true)

## Installation
0. Clone this repository somewhere or download `tracer.py`
1. Download Jython (http://www.jython.org/downloads.html) and install it anywhere you like.
2. In Burp Suite, go to Extender > Options > Python Environment > Select File
3. In the browsing window, go to the install location of Jython and select jython.jar
4. In Burp Suite, go to Extender > Extensions > Add
5. In the Extension Type dropdown, select Python
6. In the Extension File field, select the `tracer.py` file that you acquired earlier
7. A new Tracer tab should pop up in Burp Suite

## Usage
It's simple. Just click "Start" and wait for it to complete.

The output tree's hierarchy is formatted in the following order:
* Input Website
* Input Endpoint
* Input Request
* Input Parameter
* Output Website
* Output Endpoint
* Output Request
* Output Excerpts
              
This way, you can see the corresponding responses where each input value is rendered.
