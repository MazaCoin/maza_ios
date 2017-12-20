//
//  InterfaceController.swift
//  WatchApp Extension
//
//  Copyright © 2016 Aaron Voisine. All rights reserved.
//

import WatchKit
import Foundation

class InterfaceController: WKInterfaceController {
    @IBOutlet var setupWalletMessageLabel: WKInterfaceLabel! {
        didSet{
            setupWalletMessageLabel.setHidden(true)
        }
    }
    @IBOutlet var loadingIndicator: WKInterfaceGroup!

    override func awake(withContext context: Any?) {
        super.awake(withContext: context)
        
        // Configure interface objects here.
    }

    override func willActivate() {
        // This method is called when watch view controller is about to be visible to user
        super.willActivate()
        updateUI()
        
        NotificationCenter.default.addObserver(
            self, selector: #selector(InterfaceController.updateUI), name: NSNotification.Name(rawValue: BRAWWatchDataManager.WalletStatusDidChangeNotification), object: nil)
        NotificationCenter.default.addObserver(
            self, selector: #selector(InterfaceController.txReceive(_:)), name: NSNotification.Name(rawValue: BRAWWatchDataManager.WalletTxReceiveNotification), object: nil)
 
    }

    override func didDeactivate() {
        // This method is called when watch view controller is no longer visible
        super.didDeactivate()
        NotificationCenter.default.removeObserver(self)
    }
    
    func updateUI() {
        switch BRAWWatchDataManager.sharedInstance.walletStatus {
        case .unknown:
            loadingIndicator.setHidden(false)
            setupWalletMessageLabel.setHidden(true)
        case .notSetup:
            loadingIndicator.setHidden(true)
            setupWalletMessageLabel.setHidden(false)
        case .hasSetup:
            WKInterfaceController.reloadRootControllers(
                withNames: ["BRAWBalanceInterfaceController","BRAWReceiveMoneyInterfaceController"], contexts: [])
        }
    }
    
    @objc func txReceive(_ notification: Notification?) {
        print("root view controller received notification: \(String(describing: notification))")
        if let userData = notification?.userInfo,
            let noteString = userData[NSLocalizedDescriptionKey] as? String {
                self.presentAlert(
                    withTitle: noteString, message: nil, preferredStyle: .alert, actions: [
                        WKAlertAction(title: NSLocalizedString("OK", comment: ""),
                            style: .cancel, handler: { self.dismiss() })])
        }
    }

}
