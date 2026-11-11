BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.9711/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i7-13620H 2.40GHz, 1 CPU, 16 logical and 10 physical cores
.NET SDK 10.0.401
  [Host]   : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

| Method                                    | TreeSize | Mean            | Error             | StdDev           | Median     | Gen0   | Gen1   | Allocated |
|------------------------------------------ |--------- |----------------:|------------------:|-----------------:|-----------:|-------:|-------:|----------:|
| 'verify inclusion proof'                  | 1000     |      3,020.8 ns |       1,512.91 ns |         82.93 ns | 3,017.0 ns | 0.0496 |      - |     656 B |
| 'verify consistency proof (n/2+1 -> n)'   | 1000     |      4,745.0 ns |       1,521.73 ns |         83.41 ns | 4,702.6 ns | 0.0839 |      - |    1088 B |
| 'build inclusion proof (in-memory nodes)' | 1000     | 10,330,912.6 ns | 326,290,605.24 ns | 17,885,089.16 ns | 5,070.8 ns | 0.4120 |      - |    5176 B |
| 'encode + hash one audit entry'           | 1000     |        527.6 ns |         758.92 ns |         41.60 ns |   509.3 ns | 0.0153 |      - |     200 B |
| 'verify inclusion proof'                  | 100000   |      4,359.0 ns |       3,712.68 ns |        203.50 ns | 4,264.3 ns | 0.0763 |      - |    1048 B |
| 'verify consistency proof (n/2+1 -> n)'   | 100000   |      5,265.6 ns |       7,727.01 ns |        423.54 ns | 5,351.6 ns | 0.1221 |      - |    1536 B |
| 'build inclusion proof (in-memory nodes)' | 100000   |      3,002.6 ns |       4,701.77 ns |        257.72 ns | 2,865.1 ns | 0.6752 | 0.0076 |    8472 B |
| 'encode + hash one audit entry'           | 100000   |        254.5 ns |          82.88 ns |          4.54 ns |   252.8 ns | 0.0157 |      - |     200 B |
| 'verify inclusion proof'                  | 1000000  |      4,283.2 ns |       2,025.25 ns |        111.01 ns | 4,241.5 ns | 0.0916 |      - |    1216 B |
| 'verify consistency proof (n/2+1 -> n)'   | 1000000  |      7,875.4 ns |      10,223.10 ns |        560.36 ns | 8,028.0 ns | 0.1373 |      - |    1784 B |
| 'build inclusion proof (in-memory nodes)' | 1000000  |      4,660.1 ns |       5,858.41 ns |        321.12 ns | 4,754.9 ns | 0.7324 | 0.0076 |    9248 B |
| 'encode + hash one audit entry'           | 1000000  |        332.2 ns |         454.34 ns |         24.90 ns |   345.9 ns | 0.0157 |      - |     200 B |
