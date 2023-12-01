# Easy method to determine service port name by port number
from socket import getservbyname, getservbyport
import numpy as np
from scipy.stats import entropy
from data.dataObjects import *
from copy import copy

import matplotlib
# Make sure that we are using QT5
matplotlib.use('Qt5Agg')
import matplotlib.pyplot as plt
from PyQt5 import QtWidgets
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
    
####################
# Print functions
####################
def print_unknown_raw(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object and search for packets with un-decoded data.
    Print data information and raw data bytes.
    """
    for p in inPackets:
        if '<TCP Layer>' not in str(p.layers) or 'DATA' != p.highest_layer:
            continue
        # Check direction, assume smaller port is server and application
        # TODO: should probably do the same for UDP
        if p.tcp.srcport > p.tcp.dstport:
            dir = 'Query:           '
        else:
            dir = 'Response:'
        try:
            print("%s: %s:%s -> %s:%s %s %s Len: %s"%(p.frame_info.number,p.ip.src,p.tcp.srcport,p.ip.dst,p.tcp.dstport,dir,p.DATA.data,int(len(p.DATA.data)/2)))
            print("%s Raw: %s"%(' '*46,bytes.fromhex(p.DATA.data)))
        except:
            continue

def print_entropy(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object and search for packets with un-decoded data.
    Print data information and the entropy of the raw data.
    """
    # We might get Numpy divide error. Suppress it.
    np.seterr(invalid='ignore')
    # By default, limit to entropy greater than or equal to 4. Change this to 0 to get all
    # TODO: make min_ent configurable
    min_ent = 4.0
    for p in inPackets:
        if '<TCP Layer>' not in str(p.layers) or 'DATA' != p.highest_layer:
            continue
        # Check direction, assume smaller port is server and application
        # TODO: should probably do the same for UDP
        if p.tcp.srcport > p.tcp.dstport:
            dir = 'Query:           '
        else:
            dir = 'Response:'
        try:
            #print("%s: %s:%s -> %s:%s %s %s Len: %s"%(p.frame_info.number,p.ip.src,p.tcp.srcport,p.ip.dst,p.tcp.dstport,dir,p.DATA.data,int(len(p.DATA.data)/2)))
            # Review the bytes' entropy value. Values >= 7 may be encrypted or compressed
            ent_calc = round(entropy(np.frombuffer(bytes.fromhex(p.DATA.data),dtype=np.uint32)),2)
            #print("Frame Number: %s ENT: %s"%(p.frame_info.number,round(entropy(np.frombuffer(bytes.fromhex(p.DATA.data),dtype=np.uint32)),2)))
            if ent_calc >= min_ent: print("Frame Number: %s ENT: %s"%(p.frame_info.number,ent_calc))
        except:
            # TODO: FIXME the data length is not always correct
            continue


def print_histogram(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object.
    Track and print a histogram of data bytes to use for detecting of the raw data.
    """
    # We might get Numpy divide error. Suppress it.
    np.seterr(invalid='ignore')
    ########################################
    # Track each edge to track the histogram of bytes for that specific edge.
    # Edges are the host IP addresses and a port number. The direction of
    # traffic doesn't matter. The lowest port number is ther server's port.
    # This might affect some protocols like CIP on 44818.
    # edge = (ip1,ip2,port)
    # hist_list = {edge:{byte0:cnt,byte1:cnt,...},edge:{byte0:cnt,byte1:cnt,...},...}
    ########################################
    hist_list = {}
    # Set up a default historgram list to use for each new edge
    default_hist = {}
    for b in range(0,256): default_hist[b] = 0
    for p in inPackets:
        # Check packet for TCP and data
        # TODO: Maybe we should just grab tcp/udp payload?
        # TODO: should probably do the same for UDP
        if '<TCP Layer>' not in str(p.layers) or 'DATA' != p.highest_layer:
            continue
        data = p.DATA.data

        # Check direction, assume smaller port is server and application
        pport = 0
        if p.tcp.srcport < p.tcp.dstport:
            dir = 'Query:'
            pport = p.tcp.srcport
        else:
            dir = 'Response:'
            pport = p.tcp.dstport

        # Find the current edge and start tracking
        curr_edge = ()
        for e in hist_list.keys():
            if p.ip.src in e and p.ip.dst in e and pport in e:
                # Edge is in our list
                curr_edge = e
                break
        
        # We did not find an edge in our list, so make a new one.
        if not curr_edge:
            curr_edge = (p.ip.src,p.ip.dst,pport)
            hist_list[curr_edge] = copy(default_hist)

        # Enumerate the count for each byte in data and update histrogram
        for e in p.DATA.data:
            hist_list[curr_edge][ord(e)] += 1

        # Print the results of the nodes and edges
        #plot_data_print(hist_list)
        print("Running single histograms. They will appear one at a time and need to be closed after review.")
        plot_singles(hist_list)
        #plot_single_win(hist_list)
        #plot_qt5_window(hist_list)

def plot_data_print(hl):   
    # Print each table for debugging
    for edge in hl.keys():
        print('Edge: %s\n%s\n'%(edge,hl[edge]))

# Print one edge plot at a time. Close to see next window.
def plot_singles(hl):
    # Print edges one at a time
    for edge in hl.keys():
        keys = hl[edge].keys()
        vals = hl[edge].values()
        plt.bar(keys,vals)
        plt.xlabel("Byte Value")
        plt.ylabel("Count")
        plt.title('Edge %s --- %s --- %s'%(edge[0],edge[2],edge[1]))
    plt.show()
    
# Print single window with all edge plots
def plot_single_win(hl):
    # Print edge plots on single window
    plt_rows = int(len(hl) / 3) + 1
    plt_cols = 3
    row,col = 0,0
    figure, axis = plt.subplots(plt_rows, plt_cols)
    for edge in hl.keys():
        keys = hl[edge].keys()
        vals = hl[edge].values()
        #print("Keys: %s"%(keys))
        #print("Values: %s"%(vals))
        axis[row,col] = plt.bar(keys,vals)
        axis[row,col] = plt.xlabel("Byte Value")
        axis[row,col] = plt.ylabel("Count")
        axis[row,col] = plt.title('Edge %s --- %s --- %s'%(edge[0],edge[2],edge[1]))
        col += 1
        if col > 2:
            row +=1
            col = 0
    plt.show()

def plot_qt5_window(hl):
    # Print edge plots on single window
    plt_rows = int(len(hl) / 3) + 1
    plt_cols = 3
    row,col  = 0,0
    figure, axis = plt.subplots(plt_rows, plt_cols)
    for edge in hl.keys():
        keys = hl[edge].keys()
        vals = hl[edge].values()
        axis[row,col] = plt.bar(keys,vals)
        axis[row,col] = plt.xlabel("Byte Value")
        axis[row,col] = plt.ylabel("Count")
        axis[row,col] = plt.title('Edge %s --- %s --- %s'%(edge[0],edge[2],edge[1]))
        col += 1
        if col > 2:
            row +=1
            col = 0

    # pass the figure to the custom window
    a = ScrollableWindow(figure)

class ScrollableWindow(QtWidgets.QMainWindow):
    def __init__(self, fig):
        self.qapp = QtWidgets.QApplication([])

        QtWidgets.QMainWindow.__init__(self)
        self.widget = QtWidgets.QWidget()
        self.setCentralWidget(self.widget)
        self.widget.setLayout(QtWidgets.QVBoxLayout())
        self.widget.layout().setContentsMargins(0,0,0,0)
        self.widget.layout().setSpacing(0)

        self.fig = fig
        self.canvas = FigureCanvas(self.fig)
        self.canvas.draw()
        self.scroll = QtWidgets.QScrollArea(self.widget)
        self.scroll.setWidget(self.canvas)

        self.nav = NavigationToolbar(self.canvas, self.widget)
        self.widget.layout().addWidget(self.nav)
        self.widget.layout().addWidget(self.scroll)

        self.show()
        exit(self.qapp.exec_()) 