<h1 align="center">Toolkit for Retrieval and Analysis of Cyber Evidence (TRACE)</h1>

<p align="center">
  TRACE is a digital forensic tool I developed as my final year project. It provides an intuitive interface for analyzing disk images and includes a range of functionalities to assist forensic examiners in extracting and viewing the contents of various image file formats.
</p>

<p align="center">
  <img src="Icons/logo_prev_ui.png" alt="TRACE Logo" width="300"/>
</p>

<hr>

## Preview 👀
<p>
  <br/>
  <img src="Icons/readme/Preview.png" alt="TRACE Preview" width="90%"/>
  <br/>
</p>

<hr>

## Features 🌟

✅ **Image Mounting & Dismounting**: Seamlessly mount and dismount forensic disk images for analysis.\
✅ **Tree Viewer**: Navigate through the disk image structure, including partitions and files.\
✅ **Detailed File Analysis**: View file content in different formats, such as HEX, text, and application-specific views.\
✅ **EXIF Data Extraction**: Extract and display EXIF metadata from image files.\
✅ **Registry Viewer**: View and analyze Windows registry files.\
✅ **Basic File Carving**: Recover deleted files from disk images.\
✅ **Virus Total API Integration**: Check files for malware using the Virus Total API.\
✅ **E01 Image Verification**: Verify the integrity of E01 disk images.\
✅ **Convert E01 to Raw**: Convert E01 disk images to raw format.\
✅ **Message Decoding**: Decode messages from base64, binary, and other encodings.

<hr>

## Screenshots 📸

### Registry Browser 🗂️

<p>
  <br/>
  <img src="Icons/readme/registry.png" alt="Registry Browser" width="70%"/>
  <br/>
  <em>Figure 1: Viewing and analyzing Windows registry files.</em>
</p>



### File Carving 🔪

<p>
  <br/>
  <img src="Icons/readme/carving.png" alt="File Carving" width="70%"/>
  <br/>
  <em>Figure 2: Recovering deleted files from disk images.</em>
</p>



### Image Verification ✅

<p>
  <br/>
  <img src="Icons/readme/trace_verify.png" alt="Image Verification" width="50%"/>
  <br/>
  <em>Figure 3: Verifying the integrity of E01 disk images.</em>
</p>


<hr>

## Supported Image Formats 💾

| Image Format                                   | Extensions                     | Split   |  Unsplit |
|------------------------------------------------|--------------------------------|---------|----------|
| EnCase® Image File (EVF / Expert Witness Format)| `*.e01`                       | ✔️      | ✔️       |
| SMART/Expert Witness Image File                | `*.s01`                        | ✔️      | ✔️       |
| Single Image Unix / Linux DD / Raw             | `*.dd`, `*.img`, `*.raw`       | ✔️      | ✔️       |
| ISO Image File                                 | `*.iso`                        |         | ✔️       |
| AccessData Image File                          | `*.ad1`                        | ✔️       | ✔️        |

<hr>

## Getting Started 🚀


### Prerequisites

- Ensure you have all the necessary Python libraries installed.

```bash
pip install -r requirements.txt
  ```

### Running the Tool

```bash
python main.py
```

<hr>

## Built With 🧱

- [pytsk3](https://pypi.org/project/pytsk3/) - Python bindings for the SleuthKit
- [libewf-python](https://github.com/libyal/libewf) - Library to access the Expert Witness Compression Format (EWF)
- [PySide6](https://pypi.org/project/PySide6/) - Used for the GUI components.
- [Arsenal Image Mounter](https://arsenalrecon.com/products/image-mounter/) - For mounting forensic disk images.

<hr>

## Socials 👨‍💻


[![LinkedIn](https://img.shields.io/badge/LinkedIn-%230077B5.svg?logo=linkedin&logoColor=white)](https://linkedin.com/in/radoslav-gadzhovski)

<br>
<hr>

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)


