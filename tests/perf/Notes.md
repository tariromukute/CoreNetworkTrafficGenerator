# Notes

Using function performs better. For a traffic generator the difference is significant

```
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_1.py 
9.086207874999673
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_2.py
8.541262541999458
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_3.py
11.981229375000112
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_4.py
11.82600900000034
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_5.py
9.14311749999979
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_6.py
14.053624749998562
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_7.py
9.448569165997469
```

When pass arg

```
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_args_1.py
27.627659833000507
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_args_2.py
18.568473999999696
tariromukute@Tariros-MacBook-Pro cn-tg % python3 tests/perf/struct_args_3.py
18.5329356250003
```