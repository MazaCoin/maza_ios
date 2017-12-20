//
//  BRAWGlanceInterfaceController.swift
//  BreadWallet
//
import WatchKit
// FIXME: comparison operators with optionals were removed from the Swift Standard Libary.
// Consider refactoring the code to use the non-optional operators.
fileprivate func < <T : Comparable>(lhs: T?, rhs: T?) -> Bool {
  switch (lhs, rhs) {
  case let (l?, r?):
    return l < r
  case (nil, _?):
    return true
  default:
    return false
  }
}

// FIXME: comparison operators with optionals were removed from the Swift Standard Libary.
// Consider refactoring the code to use the non-optional operators.
fileprivate func <= <T : Comparable>(lhs: T?, rhs: T?) -> Bool {
  switch (lhs, rhs) {
  case let (l?, r?):
    return l <= r
  default:
    return !(rhs < lhs)
  }
}


class GlanceInterfaceController: WKInterfaceController {
    
    @IBOutlet var setupWalletContainer: WKInterfaceGroup!
    @IBOutlet var balanceAmountLabel: WKInterfaceLabel!
    @IBOutlet var balanceInLocalCurrencyLabel: WKInterfaceLabel!
    @IBOutlet var lastTransactionLabel: WKInterfaceLabel!
    @IBOutlet var balanceInfoContainer: WKInterfaceGroup!
    @IBOutlet var loadingIndicator: WKInterfaceGroup!
    override func awake(withContext context: Any?) {
        super.awake(withContext: context)
        // Configure interface objects here.
        updateUI()
    }
    
    override func willActivate() {
        // This method is called when watch view controller is about to be visible to user
        super.willActivate()
        BRAWWatchDataManager.sharedInstance.setupTimer()
        updateUI()
        NotificationCenter.default.addObserver(
            self, selector: #selector(GlanceInterfaceController.updateUI), name: NSNotification.Name(rawValue: BRAWWatchDataManager.ApplicationDataDidUpdateNotification), object: nil)
    }
    
    override func didDeactivate() {
        // This method is called when watch view controller is no longer visible
        super.didDeactivate()
        BRAWWatchDataManager.sharedInstance.destoryTimer()
        NotificationCenter.default.removeObserver(self)
    }
    
    func updateUI() {
        // when local currency rate is no avaliable, use empty string
        updateContainerVisibility()
        
        if (BRAWWatchDataManager.sharedInstance.balanceInLocalCurrency?.characters.count <= 2) {
            balanceInLocalCurrencyLabel.setHidden(true)
        } else {
            balanceInLocalCurrencyLabel.setHidden(false)
        }
        balanceAmountLabel.setAttributedText(BRAWWatchDataManager.sharedInstance.balanceAttributedString())
        balanceInLocalCurrencyLabel.setText(BRAWWatchDataManager.sharedInstance.balanceInLocalCurrency)
        lastTransactionLabel.setText(BRAWWatchDataManager.sharedInstance.lastestTransction)
    }
    
    func shouldShowSetupWalletInterface()->Bool {
        return false;
    }
    
    func updateContainerVisibility() {
        switch BRAWWatchDataManager.sharedInstance.walletStatus {
            case .unknown:
                loadingIndicator.setHidden(false)
                balanceInfoContainer.setHidden(true)
                setupWalletContainer.setHidden(true)
            case .notSetup:
                loadingIndicator.setHidden(true)
                balanceInfoContainer.setHidden(true)
                setupWalletContainer.setHidden(false)
            case .hasSetup:
                loadingIndicator.setHidden(true)
                balanceInfoContainer.setHidden(false)
                setupWalletContainer.setHidden(true)
        }
    }
}
