import pandas as pd
import glob

# Path to all CSV files (adjust path if needed)
csv_files = glob.glob("datasets_folder/*.csv")  # e.g., "data/*.csv"

# Read and concatenate all into a single DataFrame
combined_df = pd.concat([pd.read_csv(file) for file in csv_files], ignore_index=True)

# Save the final combined dataset
combined_df.to_csv("combined_college_data.csv", index=False)

print("All datasets combined successfully.")
