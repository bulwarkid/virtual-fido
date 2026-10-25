//
//  ContentView.swift
//  USBDriverInstaller
//
//  Created by Chris de la Iglesia on 12/30/22.
//

import SwiftUI

struct ContentView: View {
    @StateObject var viewModel: ContentViewModel = .init()
    
    var body: some View {
        VStack(spacing: 20) {
            Button {
                self.viewModel.activate()
            } label: {
                Text("Install Dext")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            
            Button {
                self.viewModel.deactivate()
            } label: {
                Text("Uninstall Dext")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .frame(width: 300, height: 150)
        .padding()
        .alert(isPresented: $viewModel.showAlert) {
            Alert(
                title: Text("Dext Installer"),
                message: Text(viewModel.alertMessage ?? "Unknown status"),
                dismissButton: .default(Text("OK"))
            )
        }
        .onAppear {
            if CommandLine.arguments.contains("--install") {
                viewModel.onCompletion = { success in
                    exit(success ? 0 : 1)
                }
                viewModel.activate()
            } else if CommandLine.arguments.contains("--uninstall") {
                viewModel.onCompletion = { success in
                    exit(success ? 0 : 1)
                }
                viewModel.deactivate()
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
