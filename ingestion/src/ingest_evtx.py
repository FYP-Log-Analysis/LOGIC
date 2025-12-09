import os
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

# Input folder: where the .evtx files are stored
RAW_DIR = "../../data/raw_logs/"

# Output folder: where converted XML files will be saved
OUT_DIR = "../../data/processed/"


def ingest():
    """
    Converts every .evtx file in RAW_DIR into a simple XML file.

    Steps:
    1. Look for .evtx files in the raw logs directory.
    2. Convert each file to XML using the python-evtx library.
    3. Save the resulting XML into the processed directory.

    The output XML files are easier to inspect and will be used
    by the parser in the next stage of the pipeline.
    """

    # Collect all evtx files from the input directory
    evtx_files = [f for f in os.listdir(RAW_DIR) if f.endswith(".evtx")]

    for filename in evtx_files:
        input_path = os.path.join(RAW_DIR, filename)
        output_path = os.path.join(OUT_DIR, filename.replace(".evtx", ".xml"))

        # Read and convert the evtx file
        with Evtx(input_path) as evtx_log:
            with open(output_path, "w") as xml_output:
                for xml_event, _ in evtx_file_xml_view(evtx_log):
                    xml_output.write(xml_event + "\n")

        print(f"Finished converting {filename} → {output_path}")


if __name__ == "__main__":
    ingest()
