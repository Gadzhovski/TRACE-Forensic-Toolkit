
# Trace

Trace is a digital forensic tool designed to provide an intuitive interface for analyzing disk images. It offers a range of functionalities to assist forensic examiners in extracting and viewing the contents of various image file formats.

## Features

- **Image Mounting & Dismounting**: Seamlessly mount and dismount forensic disk images for analysis.
- **Tree Viewer**: Navigate through the disk image structure, including partitions and files.
- **Detailed File Analysis**: View file content in different formats, such as HEX, text, and application-specific views.
- **EXIF Data Extraction**: Extract and display EXIF metadata from image files.
- **PDF Viewer**: Built-in PDF viewer for analyzing PDF files within the disk images.
- **Custom Icons**: Different file types are represented with custom icons for easy identification.
- **Backend Integration**: Uses powerful backend tools like The Sleuth Kit and Arsenal Image Mounter.

## Getting Started

### Prerequisites

- Ensure you have all the necessary Python libraries installed. Check `requirements.txt` for the list of libraries.
- Arsenal Image Mounter should be placed in the `tools/` directory if you're using it for mounting.
- The Sleuth Kit binaries should be available in your system's PATH or in the `tools/` directory.

### Running the Tool

```bash
python main.py
```

## Built With

- [PySide6](https://pypi.org/project/PySide6/) - Used for the GUI components.
- [Arsenal Image Mounter](https://arsenalrecon.com/products/image-mounter/) - For mounting forensic disk images.
- [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/) - Command line tools for analyzing disk images.

## Author

**Radoslav Gadzhovski**  
- [GitHub Profile](https://github.com/Gadzhovski)
- [LinkedIn Profile](https://www.linkedin.com/in/radoslav-gadzhovski/)
- Email: gadzhovski9@gmail.com

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

