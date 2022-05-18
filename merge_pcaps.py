import os
import subprocess
import argparse
from multiprocessing import Pool


def create_log_dir(log_dir="/tmp/measurements"):
    try:
        # os.mkdir(log_dir)
        os.system("mkdir -p {}".format(log_dir))
    except OSError:
        print("Creation of the log directory {} failed".format(log_dir))
    else:
        print("Successfully created the log directory {}".format(log_dir))


def merger_job(comb_file, in_file, out_file, measurements_dir):
    cmd = f"mergecap -F nsecpcap -w {comb_file + '.unordered'} {measurements_dir + in_file} {measurements_dir + out_file}"
    print(cmd)
    merger = subprocess.Popen("{}".format(cmd), shell=True)
    merger.wait()
    cmd = f"reordercap {comb_file + '.unordered'} {comb_file}"
    print(cmd)
    reorder = subprocess.Popen("{}".format(cmd), shell=True)
    reorder.wait()
    cmd = f"rm {comb_file + '.unordered'}"
    print(cmd)
    delete = subprocess.Popen("{}".format(cmd), shell=True)
    delete.wait()


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('indir', help='Specify directory of unfiltered core logs/pcaps.',
                        default='../logs/measurements/VarParams/download')
    parser.add_argument('outdir', help='Specify directory for filtered core logs/pcaps.',
                        default='../logs/measurements/VarParams/download-filtered')
    parser.add_argument('--identifier', help='Specify an identifier (e.g. .core) added before .pcap.',
                        default='.core')
    args = parser.parse_args()

    measurements_dir = os.path.abspath(args.indir) + "/"
    merged_measurements_dir = os.path.abspath(args.outdir) + "/"

    create_log_dir(merged_measurements_dir)

    all_files = []

    for (dirpath, dirnames, filenames) in os.walk(measurements_dir):
        all_files.extend(sorted(filenames))
        break

    in_files = sorted([file for file in all_files if "in." in file])
    out_files = sorted([file for file in all_files if "out." in file])
    assert len(in_files) == len(out_files), "Number of in and out files do not match!"
    comb_files = []
    for in_file, outfiles in zip(in_files, out_files):
        # to rename the files afterwards e.g. from .comb.pcap to .core.pcap
        # rename (-n) 's/.comb./.core./' /tmp/merged/*.comb.*
        comb_file = in_file.replace("in.", "").replace(".pcap", f"{args.identifier}.pcap")
        comb_files.append(merged_measurements_dir + comb_file)

    # print(comb_files)

    jobs = []
    with Pool() as pool:
        for comb_file, in_file, out_file in zip(comb_files, in_files, out_files):
            jobs.append(pool.apply_async(merger_job, args=[comb_file, in_file, out_file, measurements_dir]))

        for job in jobs:
            job.get()
