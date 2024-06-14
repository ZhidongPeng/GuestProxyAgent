﻿// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestScenarios
{
    public class ProxyAgentExtension : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            if (!Constants.IS_WINDOWS())
            {
                AddTestCase(new SetupCGroup2TestCase("SetupCGroup2"));
                AddTestCase(new RebootVMCase("RebootVMCaseAfterSetupCGroup2"));
                AddTestCase(new AddLinuxVMExtensionCase("AddLinuxVMExtensionCase"));
            } else {
                EnableProxyAgent = true;
            }
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseBeforeUpdate"));
            AddTestCase(new InstallOrUpdateGuestProxyAgentExtensionCase());
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseAfterUpdate"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot"));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterUpdateGuestProxyAgentExtension"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot"));
        }
    }
}
