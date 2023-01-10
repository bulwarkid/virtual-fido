//
//  ContentView.swift
//  USBDriverInstaller
//
//  Created by Chris de la Iglesia on 12/30/22.
//

import SwiftUI

struct ContentView: View {
    var viewModel: ContentViewModel = .init()
    var body: some View {
        VStack {
            Button {
                self.viewModel.activate()
            } label: {
                Text("Install Dext")
            }
            Button {
                self.viewModel.deactivate()
            } label: {
                Text("Uninstall Dext")
            }

                
    

        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
