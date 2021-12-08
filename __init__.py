import os
import requests
import shutil
from zipfile import ZipFile
from tempfile import TemporaryDirectory
from PySide2.QtWidgets import (QPushButton, QWidget, QVBoxLayout,
    QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
    QMessageBox, QHeaderView)
from PySide2.QtCore import Qt, QFileInfo, QUrl

from PySide2.QtGui import QDesktopServices, QKeySequence
from PySide2.QtWebEngineWidgets import QWebEnginePage, QWebEngineView, QWebEngineProfile

from binaryninja import user_plugin_path
from binaryninja.log import log_error, log_debug, log_info
from binaryninja.types import Type, Symbol, Structure
from binaryninja.plugin import PluginCommand
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.interaction import get_open_filename_input, show_message_box
from .svdmmap import parse


svdPath = os.path.realpath(os.path.join(user_plugin_path(), "..", "svd"))
try:
    if not os.path.exists(svdPath):
        os.mkdir(svdPath)
except IOError:
    log_error(f"SVD Browser: Unable to create {svdPath}")

class SVDBrowser(QDialog):
    def __init__(self, context, parent=None):
        super(SVDBrowser, self).__init__(parent)
        QWebEngineProfile.defaultProfile().downloadRequested.connect(self.on_downloadRequested)

        # Create widgets
        #self.setWindowModality(Qt.ApplicationModal)
        self.title = QLabel(self.tr("SVD Browser"))
        self.closeButton = QPushButton(self.tr("Close"))
        self.setWindowTitle(self.title.text())
        self.browseButton = QPushButton("Browse SVD Folder")
        self.deleteSvdButton = QPushButton("Delete")
        self.applySvdButton = QPushButton("Apply SVD")
        self.view = QWebEngineView()
        url = "https://developer.arm.com/tools-and-software/embedded/cmsis/cmsis-search"
        self.view.load(QUrl(url))
        self.columns = 3
        self.context = context

        self.currentFileLabel = QLabel()
        self.currentFile = ""

        #Files
        self.files = QFileSystemModel()
        self.files.setRootPath(svdPath)
        self.files.setNameFilters(["*.svd", "*.patched"])

        #Tree
        self.tree = QTreeView()
        self.tree.setModel(self.files)
        self.tree.setSortingEnabled(True)
        self.tree.hideColumn(2)
        self.tree.sortByColumn(0, Qt.AscendingOrder)
        self.tree.setRootIndex(self.files.index(svdPath))
        for x in range(self.columns):
            #self.tree.resizeColumnToContents(x)
            self.tree.header().setSectionResizeMode(x, QHeaderView.ResizeToContents)
        treeLayout = QVBoxLayout()
        treeLayout.addWidget(self.tree)
        treeButtons = QHBoxLayout()
        #treeButtons.addWidget(self.newFolderButton)
        treeButtons.addWidget(self.browseButton)
        treeButtons.addWidget(self.applySvdButton)
        treeButtons.addWidget(self.deleteSvdButton)
        treeLayout.addLayout(treeButtons)
        treeWidget = QWidget()
        treeWidget.setLayout(treeLayout)

        # Create layout and add widgets
        buttons = QHBoxLayout()
        buttons.addWidget(self.closeButton)

        vlayoutWidget = QWidget()
        vlayout = QVBoxLayout()
        vlayout.addWidget(self.view)
        vlayout.addLayout(buttons)
        vlayoutWidget.setLayout(vlayout)

        hsplitter = QSplitter()
        hsplitter.addWidget(treeWidget)
        hsplitter.addWidget(vlayoutWidget)

        hlayout = QHBoxLayout()
        hlayout.addWidget(hsplitter)

        self.showMaximized() #Fixes bug that maximized windows are "stuck"
        #Because you can't trust QT to do the right thing here

        # Set dialog layout
        self.setLayout(hlayout)

        # Add signals
        self.closeButton.clicked.connect(self.close)
        self.tree.selectionModel().selectionChanged.connect(self.selectFile)
        self.applySvdButton.clicked.connect(self.applySvd)
        self.deleteSvdButton.clicked.connect(self.deleteSvd)
        self.browseButton.clicked.connect(self.browseSvd)

    def browseSvd(self):
        url = QUrl.fromLocalFile(svdPath)
        QDesktopServices.openUrl(url)

    def selectFile(self, new, old):
        if len(new.indexes()) == 0:
            self.tree.clearSelection()
            self.currentFile = ""
            return
        newSelection = self.files.filePath(new.indexes()[0])
        if QFileInfo(newSelection).isDir():
            self.tree.clearSelection()
            self.currentFile = ""
            return
        self.currentFile = newSelection

    def applySvd(self):
        selection = self.tree.selectedIndexes()[::self.columns][0] #treeview returns each selected element in the row
        svdName = self.files.fileName(selection)
        if (svdName != ""):
            question = QMessageBox.question(self, self.tr("Confirm"), self.tr(f"Confirm applying {svdName} to {os.path.basename(self.context.file.filename)} : "))
            if (question == QMessageBox.StandardButton.Yes):
                log_debug("SVD Browser: Applying SVD %s." % svdName)
                load_svd(self.context, self.currentFile)
                self.close()

    def deleteSvd(self):
        selection = self.tree.selectedIndexes()[::self.columns][0] #treeview returns each selected element in the row
        svdName = self.files.fileName(selection)
        question = QMessageBox.question(self, self.tr("Confirm"), self.tr("Confirm deletion: ") + svdName)
        if (question == QMessageBox.StandardButton.Yes):
            log_debug("SVD Browser: Deleting SVD %s." % svdName)
            self.files.remove(selection)
            self.tree.clearSelection()

    def on_downloadRequested(self, download):
        old_path = download.url().path()  # download.path()
        suffix = QFileInfo(old_path).suffix()
        if (suffix.lower() in ["zip", "svd", "pack", "patched"]):
            log_debug(f"SVD Browser: Downloading {str(download.url())}")
            if suffix.lower() == "svd" or suffix.lower() == "patched":
                download.setDownloadDirectory(svdPath)
                download.accept()
            else:
                with TemporaryDirectory() as tempfolder:
                    log_debug(f"SVD Browser: Downloading pack/zip to {tempfolder}")
                    fname = download.url().fileName()
                    r = requests.get(download.url().toString(), allow_redirects=True)
                    dlfile = os.path.join(tempfolder, fname)
                    open(dlfile, "wb").write(r.content)
                    '''
                    # TODO: See if the original QT Downloader can be fixed since it would
                    # help with situations where the user entered credentials in the browser.
                    download.setDownloadDirectory(tempfolder)
                    download.accept()
                    while not download.finished:
                        import time
                        time.sleep(100)
                    '''
                    if fname.endswith(".zip") or fname.endswith(".pack"):
                        destFolder = os.path.join(svdPath, os.path.splitext(fname)[0])
                        log_debug(f"SVD Browser: Creating {destFolder}")
                        if not os.path.exists(destFolder):
                            os.mkdir(destFolder)
                        with ZipFile(dlfile, 'r') as zipp:
                            for ifname in zipp.namelist():
                                if ifname.endswith(".svd"):
                                    info = zipp.getinfo(ifname)
                                    info.filename = os.path.basename(info.filename)
                                    log_debug(f"SVD Browser: Extracting {info.filename} from {ifname}")
                                    zipp.extract(info, path=destFolder)
                    else:
                        #Move file into place
                        shutil.move(dlfile, svdPath)
        else:
            show_message_box("Invalid file", "That download does not appear to be a valid SVD/ZIP/PACK file.")
        download.cancel()

def launch_browser(bv):
    svd = SVDBrowser(bv)
    svd.exec_()

def load_svd(bv, svd_file = None):
    if not svd_file:
        svd_file = get_open_filename_input("SVD File")
    if isinstance(svd_file, str):
        svd_file=bytes(svd_file, encoding="utf-8")
    if not os.access(svd_file, os.R_OK):
        log_error(f"SVD Browser: Unable to open {svd_file}")
        return
    log_info(f"SVD Loader: Loading {svd_file}")
    device = parse(svd_file)
    peripherals = device['peripherals'].values()
    base_peripherals = [p for p in peripherals if 'derives' not in p]
    derived_peripherals = [p for p in peripherals if 'derives' in p]

    def register_peripheral(p, struct_type):
        bv.add_user_section(p['name'], p['base'], p['size'],
                            SectionSemantics.ReadWriteDataSectionSemantics)
        bv.add_user_segment(p['base'], p['size'], 0, 0,
                            SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        bv.define_data_var(p['base'], struct_type)
        bv.define_user_symbol(Symbol(SymbolType.ImportedDataSymbol, p['base'], p['name']))

    for p in base_peripherals:
        s = Structure()

        # Track the size of the peripheral
        periph_size = 0
        for r in p['registers'].values():
            if r['size'] is None:
                reg_size = 4
            else:
                reg_size = r['size'] // 8

            s.insert(r['offset'], Type.int(reg_size, False), r['name'])

            if r['offset'] >= periph_size:
                periph_size = r['offset'] + reg_size

        # Update the peripheral size if it is incorrect
        if p['size'] < periph_size:
            p['size'] = periph_size

        struct_type = Type.structure_type(s)
        bv.define_user_type(p['name'], struct_type)
        register_peripheral(p, struct_type)

    for p in derived_peripherals:
        struct_type = bv.get_type_by_name(device['peripherals'][p['derives']]['name'])
        register_peripheral(p, struct_type)


PluginCommand.register(
    "SVD\\SVD Browser",
    "Manage SVD files and browse/search for new files to load.",
    launch_browser
)

PluginCommand.register(
    "SVD\\Load SVD",
    "Apply an SVD's memory map",
    load_svd
)
