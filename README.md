# Azure DevOps TLS 1.2 transition readiness checker

Azure DevOps Services (as many other Microsoft services) is undergoing transition to deprecate transport protocols TLS 1.0, TLS 1.1 and some TLS 1.2 cipher suites which are considered weak.

See announcement from Azure DevOps team here: https://devblogs.microsoft.com/devops/deprecating-weak-cryptographic-standards-tls-1-0-and-1-1-in-azure-devops-services/

The purpose of this project is to simplify the task of preparation for the transition.
We gathered most frequently seen TLS-compatibility issues reported by our customers and made a script which detects them and points the user towards the mitigation.


Run the script:
```ps
AzureDevOpsTls12Analysis.ps1
````
Run in Powershell version 4 or higher. Windows-only, the script has been tested on Windows Server 2012 R2 and above.

What the script does:
- performs a probe by opening a test connection to one of Azure DevOps Services sites which have already fully migrated to TLS 1.2 with strong cipher suites.
- performs an analysis of OS-level issues by looking at selected Windows registry spots known to be sources of TLS-incompatibilities and misconfigurations. OS-level issues are shared by all the software running on the machine that uses OS's HTTPS/TLS stack.
- performs an analysis of .NET Framework configuration in Windows registry that can be used to make old .NET applications (applications built against old versions of .NET Framework) to leverage all OS's TLS capabilities. 

What the script does not:
- The script does not execute any mitigations that would make your computer TLS 1.2-ready.
- The script does not need elevated permissions to run.
- The script cannot say if specific app will have TLS issues. There are apps which have TLS/SSL version hard-code or configured. 

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
