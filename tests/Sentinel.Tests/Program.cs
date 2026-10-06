using Sentinel.Tests;

var tests = new TestRunner();
await CoreTests.Run(tests);
await RepositoryTests.Run(tests);
await ReportingTests.Run(tests);
await EngineContractTests.Run(tests);
await CoordinatorTests.Run(tests);
await ServiceSecurityTests.Run(tests);
return tests.Finish();
