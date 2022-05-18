#! /usr/bin/python3

import numpy as np
import statsmodels.api as sm
import matplotlib.pyplot as plt
import sys
import collections

sys.path.append("..")
import pcap_parser
import os
from multiprocessing import Pool
import argparse
import plotting
import close_to_one


class Plot:
    def __init__(self, logdir, labels=None):
        self.logdir = os.path.expanduser(logdir) + "/"
        self.pp_dict = {}

        # file_dict = {pktSize: pktRates: numPkts}
        self.file_dict = {}
        self.results_dict = {}
        self.scenario_results_dict = None

    def analyze(self, filter='', core="Nokia"):
        with Pool() as pool:
            files = pcap_parser.find_pcap_files(self.logdir, core=True)

            self.pp_dict = collections.defaultdict(lambda: collections.defaultdict(None))

            self.file_dict = collections.defaultdict(lambda: collections.defaultdict(None))

            workers_dict = collections.defaultdict(lambda: collections.defaultdict(None))

            for file in files:
                if not filter in file:
                    continue
                pktsize, pktrate = file.split("/")[-1].split(".")[:-1][-3:-1]  # .128.10.core.pcap
                self.pp_dict[pktsize][pktrate] = pcap_parser.PCAPParser(file=file)
                self.file_dict[pktsize][pktrate] = file
                workers_dict[pktsize][pktrate] = None

            self.results_dict = workers_dict

            opts = {"save_pickle": False, "load_pickle": True, "core_type": core}

            for pktsize in self.file_dict.keys():
                for pktrate in self.file_dict[pktsize].keys():
                    file = self.file_dict[pktsize][pktrate]
                    workers_dict[pktsize][pktrate] = pool.apply_async(
                        self.pp_dict[pktsize][pktrate].analyze_core, args=[file], kwds=opts)

            for pktsize in workers_dict.keys():
                for pktrate in workers_dict[pktsize].keys():
                    self.results_dict[pktsize][pktrate] = workers_dict[pktsize][pktrate].get()

    def analyze_scenario(self, type="owd", **kwargs):

        workers_dict = {}
        self.scenario_results_dict = {}
        for pktSize in self.pp_dict.keys():
            workers_dict[pktSize] = {}
            self.scenario_results_dict[pktSize] = {}

        with Pool() as pool:
            for pktSize in self.file_dict.keys():
                for pktRate in self.file_dict[pktSize].keys():
                    if "owd" in type:
                        workers_dict[pktSize][pktRate] = pool.apply_async(
                            self.pp_dict[pktSize][pktRate].owdelay,
                            args=[*self.results_dict[pktSize][pktRate]])
                        # kwds={"return_seqnos": True})

            for pktSize in workers_dict.keys():
                for pktRate in workers_dict[pktSize].keys():
                    data_seqno = self.results_dict[pktSize][pktRate][0]
                    self.scenario_results_dict[pktSize][pktRate] = (
                        workers_dict[pktSize][pktRate].get(), data_seqno)

        print("Finished analyzing Scenarios.")

    def show_delay_perc_rates(self, nines=5, baseline=None, paper=False, save=None, show=True):
        if not paper:
            plotting.setup_large()
        else:
            plotting.setup_acm()

        fig, ax = plt.subplots(tight_layout=True)
        if not paper:
            ax.set_title(r"Tail-Latency Distribution")
        ax.set_xscale('close_to_one', nines=nines)
        ax.set_yscale(get_yscale(self.logdir))
        ax.set_ylabel(r'Latency ($\mu s$)')
        ax.set_xlabel(r'Percentile (\%)')
        ax.grid(True)

        pktSize = "128"
        for pktRate in sorted(self.scenario_results_dict[pktSize].keys(), key=int):
            delta_ts, seq_nos = self.scenario_results_dict[pktSize][pktRate]
            delta_ts = [delay_us for delay_us in s_to_us(delta_ts)]
            ecdf = sm.distributions.empirical_distribution.ECDF(delta_ts)
            delta_t_vals = np.linspace(min(delta_ts), max(delta_ts), num=1000)
            probs = ecdf_transform(ecdf(delta_t_vals), nines)
            ax.step(probs, delta_t_vals, label=pktRate)

        if baseline:
            delta_ts, seq_nos = baseline["128"]["10000"]
            delta_ts = [delay_us for delay_us in s_to_us(delta_ts)]
            ecdf = sm.distributions.empirical_distribution.ECDF(delta_ts)
            delta_t_vals = np.linspace(min(delta_ts), max(delta_ts), num=1000)
            probs = ecdf_transform(ecdf(delta_t_vals), nines)
            ax.step(probs, delta_t_vals, label="Baseline", color="black", linestyle="dotted")

        ax.legend(ncol=get_col(self.logdir), columnspacing=0.25, borderaxespad=0.1, labelspacing=0.125, borderpad=0.1)
        ax.set_xticklabels([f"{tick * 100:.{nines}g}" for tick in ax.get_xticks()])
        ax.set_ylim(get_ylim(self.logdir))

        if save:
            print("Save: ", save)
            plt.savefig(save, bbox_inches="tight", pad_inches=0)

        if show:
            plt.show()

        plt.close()

    def show_delay_perc_sizes(self, nines=5, baseline=None, paper=False, save=None, show=True):
        print(f"show_delay_perc_sizes")
        if not paper:
            plotting.setup_large()
        else:
            plotting.setup_acm()

        fig, ax = plt.subplots(tight_layout=True)
        if not paper:
            ax.set_title(r"Tail-Latency Distribution")
        ax.set_xscale('close_to_one', nines=nines)
        ax.set_yscale(get_yscale(self.logdir))
        ax.set_ylabel(r'Latency ($\mu s$)')
        ax.set_xlabel(r'Percentile (\%)')
        ax.grid(True)

        pktRate = "10000"
        for pktSize in sorted(self.scenario_results_dict.keys(), key=int):
            delta_ts, seq_nos = self.scenario_results_dict[pktSize][pktRate]
            delta_ts = [delay_us for delay_us in s_to_us(delta_ts)]
            ecdf = sm.distributions.empirical_distribution.ECDF(delta_ts)
            delta_t_vals = np.linspace(min(delta_ts), max(delta_ts), num=1000)
            probs = ecdf_transform(ecdf(delta_t_vals), nines)
            ax.step(probs, delta_t_vals, label=pktSize)

        if baseline:
            delta_ts, seq_nos = baseline["128"]["10000"]
            delta_ts = [delay_us for delay_us in s_to_us(delta_ts)]
            ecdf = sm.distributions.empirical_distribution.ECDF(delta_ts)
            delta_t_vals = np.linspace(min(delta_ts), max(delta_ts), num=1000)
            probs = ecdf_transform(ecdf(delta_t_vals), nines)
            ax.step(probs, delta_t_vals, label="Baseline", color="black", linestyle="dotted")

        ax.legend(ncol=get_col(self.logdir), columnspacing=0.25, borderaxespad=0.1, labelspacing=0.125, borderpad=0.1)
        ax.set_xticklabels([f"{tick * 100:.{nines}g}" for tick in ax.get_xticks()])
        ax.set_ylim(get_ylim(self.logdir))

        if save:
            print("Save: ", save)
            plt.savefig(save, bbox_inches="tight", pad_inches=0)

        if show:
            plt.show()

        plt.close()


def show_delay_perc_multiple_pktRates(scenario_results_dict_list, labels, nines=5, paper=False, save=None, show=True):
    # linestyles = ["dotted", "solid", "dashed", "dashdot"]
    linestyles = ["solid", "dotted", "dashed", "dashdot"]
    if not paper:
        plotting.setup_large()
    else:
        plotting.setup_acm()

    fig, ax = plt.subplots(tight_layout=True)
    if not paper:
        ax.set_title(r"Tail-Latency Distribution")
    ax.set_xscale('close_to_one', nines=nines)
    ax.set_yscale('log')
    ax.set_ylabel(r'Latency ($\mu s$)')
    ax.set_xlabel(r'Percentile (\%)')
    ax.grid(True)

    pktSize = "128"
    for c, scenario_results_dict in enumerate(scenario_results_dict_list):
        ax.set_prop_cycle(None)
        pkt_rates = [pktRate for pktRate in sorted(scenario_results_dict[pktSize].keys(), key=int) if
                     (pktRate == "100" or pktRate == "10000")]
        for i, pktRate in enumerate(pkt_rates):
            delta_ts, seq_nos = scenario_results_dict[pktSize][pktRate]
            delta_ts = [delay_us for delay_us in s_to_us(delta_ts)]
            ecdf = sm.distributions.empirical_distribution.ECDF(delta_ts)
            delta_t_vals = np.linspace(min(delta_ts), max(delta_ts), num=1000)
            probs = ecdf_transform(ecdf(delta_t_vals), nines)
            if i == 0:
                lines = ax.step(probs, delta_t_vals, label=labels[c], linestyle=linestyles[c], alpha=0, color="black")
                lines[0].set_alpha(1)
            ax.step(probs, delta_t_vals, label=pktRate, linestyle=linestyles[c])

    # ax.legend(ncol=len(scenario_results_dict_list), columnspacing=0.5, borderaxespad=0.1)
    ax.legend(ncol=len(scenario_results_dict_list), columnspacing=0.5, borderaxespad=0.1, labelspacing=0.125, borderpad=0.2,
              bbox_to_anchor=(0, 1.02, 1, 0.2), loc="lower left", mode="expand")
    ax.set_xticklabels([f"{tick * 100:.{nines}g}" for tick in ax.get_xticks()])
    ax.set_ylim((5, 900))

    if save:
        print("Save: ", save)
        plt.savefig(save, bbox_inches="tight", pad_inches=0)

    if show:
        plt.show()
    plt.close()


def get_ylim(file):
    ylim_dict = {"dpdk/download": (4, 28),
                 "p4/download": (4.5, 6.5),
                 "xdp/download": (4, 950)}
    for tech in ylim_dict.keys():
        if tech in file:
            return ylim_dict[tech]
    return (None, None)


def get_yscale(file):
    yscale_dict = {"dpdk/download": "linear",
                   "p4/download": "linear",
                   "xdp/download": "log",
                   "nokia/download": "log"}
    for tech in yscale_dict.keys():
        if tech in file:
            return yscale_dict[tech]
    return "linear"


def get_col(file):
    col_dict = {"dpdk/download": 3,
                "p4/download": 3,
                "xdp/download": 2,
                "nokia/download": 3}
    for tech in col_dict.keys():
        if tech in file:
            return col_dict[tech]
    return None


def xy_label_s_to_ms(ax):
    labels = [int(tick * 1000) for tick in ax.get_xticks()]
    ax.set_xticklabels(labels)
    labels = [int(tick * 1000) for tick in ax.get_yticks()]
    ax.set_yticklabels(labels)


def s_to_ms(delta_t_list):
    return [delta_t * 1000 for delta_t in delta_t_list]


def xy_label_s_to_us(ax):
    labels = [int(tick * 10 ** 6) for tick in ax.get_xticks()]
    ax.set_xticklabels(labels)
    labels = [int(tick * 10 ** 6) for tick in ax.get_yticks()]
    ax.set_yticklabels(labels)


def s_to_us(delta_t_list):
    return [delta_t * 10 ** 6 for delta_t in delta_t_list]


def ecdf_transform(probs, nines):
    probs[-1] = 1 - 10 ** (-1 - nines)
    return probs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--logdirs', help='Specify directories for logs/pcaps.',
                        default=['/tmp/dutdelay/download'], nargs='+')
    parser.add_argument('--baseline', help='Specify directories for logs/pcaps.', default=None)
    parser.add_argument('--core', help='Specify core type (GTP offset in pcap_parser).', default="Nokia")
    parser.add_argument('--labels', help='Specify labels for the logs specified with --logdirs. ', default=[''],
                        nargs='+')
    parser.add_argument('--plot-type', help='Specify plot type ("rates", "sizes", "multiple_rates").', default='rates')
    parser.add_argument('--show', help='Show plot.', action='store_true')
    parser.add_argument('--paper', help='Plots are formatted for paper.', action='store_true')
    parser.add_argument('--save', help='Save plot at specified directory.', default=None)
    parser.add_argument('--filter', help='Specify string (e.g ".128.10.") to be in file name.', default='')

    args = parser.parse_args()
    assert len(args.labels) == len(args.logdirs)

    p = {}
    baseline = None
    baseline_srd = None
    if args.baseline:
        baseline = Plot(args.baseline)
        baseline.analyze(filter=args.filter, core=args.core)
        baseline.analyze_scenario()
        baseline_srd = baseline.scenario_results_dict

    for logdir in args.logdirs:
        p[logdir] = Plot(logdir)
        p[logdir].analyze(filter=args.filter, core=args.core)
        p[logdir].analyze_scenario()
        if args.plot_type == "rates":
            p[logdir].show_delay_perc_rates(baseline=baseline_srd, paper=args.paper, save=args.save, show=args.show)
        if args.plot_type == "sizes":
            p[logdir].show_delay_perc_sizes(baseline=baseline_srd, paper=args.paper, save=args.save, show=args.show)

    scenario_results_dict_list = [p[logdir].scenario_results_dict for logdir in p.keys() if not logdir == args.baseline]
    if args.plot_type == "multiple_rates":
        show_delay_perc_multiple_pktRates(scenario_results_dict_list, args.labels, paper=args.paper, save=args.save)
