# TruffleHog Burp Extension

This repository contains a Burp Suite extension that implements TruffleHog to scan for over 800+ different types of secrets in Burp Suite HTTP traffic. All results are displayed in the `TruffleHog` tab in Burp Suite.

## Getting Started

### Prerequisites

- [Burp Suite](https://portswigger.net/burp/communitydownload)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)

If you don't have TruffleHog installed, you'll need to install it. You can see options here: https://github.com/trufflesecurity/trufflehog?tab=readme-ov-file#floppy_disk-installation

**If you already have a Burp Suite Extension using Python, follow these steps:**
1. Clone the repository to your local machine.
2. Load the extension in Burp Suite under `Extensions -> Installed -> Add -> Select Python (Extension type) > Select the trufflehog.py file`.
3. Once you load the extension, if we can't automatically find the TruffleHog binary in your PATH, you'll need to specify the path to the TruffleHog binary in the `TruffleHog` tab.

**If you don't already have a Burp Suite Extension using Python, follow these steps:**
1. Download [Jython Standalone](https://www.jython.org/download.html).
2. Specify the path to the jython-standalone jar in Burp Suite under `Settings -> Extensions -> Python environment`.
3. Clone the repository to your local machine.
4. Load the extension in Burp Suite under `Extensions -> Installed -> Add -> Select Python (Extension type) > Select the trufflehog.py file`.
5. Once you load the extension, if we can't automatically find the TruffleHog binary in your PATH, you'll need to specify the path to the TruffleHog binary in the `TruffleHog` tab.

## Configurations

There are two sets of configurations: Burp Suite and TruffleHog.

### Burp Suite

By default, the extension will only scan *proxy* traffic. You can modify the configuration in the `TruffleHog` tab to scan other Burp Suite traffic (e.g., repeater, intruder, etc.). 

### TruffleHog

By default, the extension will attempt to verify each secret that it finds (more info here: https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets). You can turn this off by deselecting the "Verify Secrets" checkbox. Also by default, the extension will **not** allow overlapping secret checks. You can turn this on by selecting the "Allow Overlapping Secret Checks" checkbox.

If we can't find the TruffleHog binary in your PATH (common when using Burp on OSX), you'll need to specify the path to the TruffleHog binary in the `TruffleHog` tab.


## How it works

After a lot of testing, we figured that the most efficient way to scan for secrets in Burp Suite was to write all of the HTTP traffic to disk in a temp directory and then invoke TruffleHog via OS command ever 10 seconds (assuming there are new files to scan). This does require some disk space, but in testing, it's really not that much. This method keeps the memory footprint of the extension low and let's us scan for secrets in Burp Suite traffic in near real-time.

## Testing

To run the tests, use the following command:
```
pytest
```

The tests only cover the scanner.py file, which contains the core functionality of the secret scanning in this extension.

## ToDo

- [ ] Add a test suite for the Burp Suite specific code (`tab_ui.py` and `trufflehog.py`).
- [ ] Add in aho-corasick keyword preflighting to HTTP header files.
- [ ] Scan WebSocket traffic.