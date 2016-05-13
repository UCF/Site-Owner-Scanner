# Site-Owner-Scanner

```
Usage: smap.py [OPTIONS] COMMAND [ARGS]...

  Map UCF site owners.

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  insert-dns-records  Insert DNS records to database.
  insert-domain-info  Insert IPMan records to database.
  scan                Start IP scanner.
  setupdb             Create database tables if needed.
```

## Install:

1. Install Virtualenv for Python2
  ```shell
  $ [sudo] pip install virtualenv
  ```

2. Create a virtual environment
  ```shell
  $ scl enable python27 bash
  $ virtualenv Site-Owner-Scanner
  $ cd "$_" || exit 1
  ```

3. Clone repo to a subdirectory
  ```shell
  $ git clone https://github.com/UCF/Site-Owner-Scanner.git src
  $ source bin/activate
  ```

4. Install dependencies via pip
  ```shell
  $ cd src || exit 1
  $ pip install -r requirements.txt
  ```

## Kudos:
* Jim Barnes

## License
> MIT License
>
> Copyright (c) 2016, Demetrius Ford &lt;Demetrius.Ford@ucf.edu&gt;

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:

> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
