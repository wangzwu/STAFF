import sys
import pandas as pd

f1, f2, fout = sys.argv[1], sys.argv[2], sys.argv[3]
df1 = pd.read_csv(f1)
df2 = pd.read_csv(f2)
df = df1.merge(df2, on="firmware", suffixes=("_1","_2"))
out = {"firmware": df["firmware"]}
for col in df1.columns[1:]:
    a, b = df[f"{col}_1"], df[f"{col}_2"]
    diff = (b - a) / a * 100
    out[col] = diff.map(lambda x: f"{x:+.2f}%")
pd.DataFrame(out).to_csv(fout, index=False)
