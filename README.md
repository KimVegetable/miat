# Multimedia Integrated Analysis Tool

*This project was created for the purpose of peer review in the context of our paper submission. If the paper is accepted, the content may be updated or revised in the future.*

---

## Paper Information

**[Paper] An in-depth forensic examination of edited videos in Apple Photos**

### Overview
With the widespread availability of mobile and desktop tools for video editing, it has become increasingly feasible for individuals to alter digital evidence in ways that serve their interests. On Apple iOS and macOS platforms, the native “Photos” application stands out for its ability to edit videos without re-encoding them, leaving behind traces of manipulation such as metadata changes and unreferenced frames. Although many video players and commercial forensic tools overlook these meaningful artifacts, they can be crucial for revealing malicious editing behavior by a suspect. In this paper, we explore how the “Photos” application can be used to manipulate video files for potentially adversarial purposes and examine its impact on the underlying file structure. We then propose and implement detection methods that cover operations such as *trimming*, *cropping*, and *rotation* to identify these manipulations and recover any residual unreferenced frames. By testing various devices and operating system versions, we demonstrate the broad applicability of our approach, showing that between 1 and 247 unreferenced frames can be recovered. As a result, our research provides the forensic community with robust methods for classifying suspicious video files, identifying their editing techniques, and extracting residual data that can be valuable as evidence.

---

## Key Features
- ✅ **Feature 1** - Parses ISOBMFF container metadata  
- ✅ **Feature 2** - Extracts metadata from H.264 and H.265 codecs  
- ✅ **Feature 3** - Extracts unreferenced frames and detects video tampering  
- ✅ **Feature 4** - We intended for this tool to analyze all detailed fields within both the container and codec domains of multimedia files. As a result, the generated JSON file may be quite large. To view large JSON files efficiently, we recommend using [HugeJsonViewer](https://github.com/WelliSolutions/HugeJsonViewer) or accessing the JSON file programmatically.

---

## Demo Video and Dataset
- [Demo Video](https://youtu.be/I4iX5NW-a2E)
- [Dataset Link](https://drive.google.com/drive/folders/1CrAOWKht3vmBBK3EgVnfm6_sYQxPvueg?usp=sharing)

---

## Usage
- If you want to use the source code directly, please download the ffmpeg.exe file and add it to the utils folder (utils/ffmpeg/ffmpeg.exe).
- The built files have been added to the release.

---

## Options

| Option       | Short             | Description                                       |
|--------------|-------------------|---------------------------------------------------|
| `--parse`    | `-p`              | Enable parse mode                                 |
| `--input`    | `-i` `<path>`     | Specify the directory containing video files      |
| `--output`   | `-o` `<path>`     | Specify the output directory                      |
| `--export`   | `-e` `json`       | Export parsed data to JSON                        |
| `--apple`    | `-a`              | Detect edited videos using Apple 'Photos'         |

---

## Example Usage
- `miat.exe -p -a --input "{absulte_path}" --output "{absulte_path}" --export json`
- `cli/main.py -p -a --input "{absulte_path}" --output "{absulte_path}" --export json`
