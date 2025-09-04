import json
import glob
import os
import matplotlib
# Set backend to Agg to avoid Qt display issues
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import pandas as pd
import math

def analyze_bb_attributes_integrated(directory_path, standard_flag=False):
    """
    Analyze basic block attributes from JSON files and create integrated box plots with 4 subplots per row
    Args:
        directory_path (str): Path to directory containing *_bb2attributes.json files
    """
    
    # Attribute names in order
    attribute_names = ['imme_num', 'string_num', 'mem_num', 'arith_num', 'indegree', 'offspring', 'betweenness']
    
    if standard_flag == False:
        # Find all *_bb2attributes.json files
        pattern = os.path.join(directory_path, "*_bb2attributes.json")
        json_files = glob.glob(pattern)
        if not json_files:
            print(f"No *_bb2attributes.json files found in {directory_path}")
            return
    else:
        # Find all *_bb2attributes_standard.json files
        pattern = os.path.join(directory_path, "*_bb2attributes_standard.json")
        json_files = glob.glob(pattern)
        if not json_files:
            print(f"No *_bb2attributes_standard.json files found in {directory_path}")
            return
    
    print(f"Found {len(json_files)} files to process...")
    
    # Collect data from all programs
    all_program_data = {}
    all_stats = []
    
    # Process each file and collect data
    for json_file in json_files:
        try:
            # Extract program name from filename
            # program_name = Path(json_file).stem.replace('_bb2attributes', '')
            program_name = Path(json_file).stem.replace('_bb2attributes_standard', '')
            print(f"Processing: {program_name}")
            
            # Read JSON data
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if not data:
                print(f"Warning: Empty data in {json_file}")
                continue
            
            # Extract attribute values from the new JSON structure
            all_attributes = []
            for bb_address, bb_data in data.items():
                if 'attributes' in bb_data and isinstance(bb_data['attributes'], list):
                    all_attributes.append(bb_data['attributes'])
                else:
                    print(f"Warning: Missing or invalid 'attributes' in basic block {bb_address}")
            
            if not all_attributes:
                print(f"Warning: No valid attributes found in {json_file}")
                continue
            
            num_basic_blocks = len(all_attributes)
            
            # Transpose to get each attribute separately
            # all_attributes is now a list of lists, where each inner list has 7 attribute values
            attributes_by_type = list(zip(*all_attributes))
            
            # Store data for integrated plotting
            all_program_data[program_name] = {
                'attributes': attributes_by_type,
                'num_blocks': num_basic_blocks
            }
            
            # Calculate statistics for this program
            program_stats = {'Program': program_name, 'Basic_Blocks': num_basic_blocks}
            for i, attr_name in enumerate(attribute_names):
                attr_values = np.array(attributes_by_type[i])
                program_stats[f'{attr_name}_mean'] = np.mean(attr_values)
                program_stats[f'{attr_name}_median'] = np.median(attr_values)
                program_stats[f'{attr_name}_std'] = np.std(attr_values)
            
            all_stats.append(program_stats)
            
        except Exception as e:
            print(f"Error processing {json_file}: {str(e)}")
            continue
    
    if not all_program_data:
        print("No valid data found!")
        return
    
    # Calculate grid dimensions (4 columns per row)
    num_programs = len(all_program_data)
    num_cols = 4
    num_rows = math.ceil(num_programs / num_cols)
    
    # Create integrated figure
    fig_width = 20
    fig_height = 5 * num_rows
    fig, axes = plt.subplots(num_rows, num_cols, figsize=(fig_width, fig_height))
    
    # Handle case where there's only one row
    if num_rows == 1:
        axes = axes.reshape(1, -1)
    elif num_cols == 1:
        axes = axes.reshape(-1, 1)
    
    # Color scheme for attributes
    colors = ['lightblue', 'lightgreen', 'lightcoral', 'lightyellow', 
             'lightpink', 'lightgray', 'lightcyan']
    
    # Plot each program
    program_names = list(all_program_data.keys())
    for idx, program_name in enumerate(program_names):
        row = idx // num_cols
        col = idx % num_cols
        ax = axes[row, col]
        
        data = all_program_data[program_name]
        attributes_by_type = data['attributes']
        num_blocks = data['num_blocks']
        
        # Create box plot
        box_plot = ax.boxplot(attributes_by_type, labels=attribute_names, patch_artist=True)
        
        # Color the boxes
        for patch, color in zip(box_plot['boxes'], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        
        # Customize subplot
        ax.set_title(f'{program_name}\n({num_blocks} blocks)', fontsize=10, fontweight='bold')
        ax.tick_params(axis='x', rotation=45, labelsize=8)
        ax.tick_params(axis='y', labelsize=8)
        ax.grid(True, alpha=0.3)
        
        # Set y-axis to log scale for better visualization
        # ax.set_yscale('log')
    
    # Remove empty subplots
    for idx in range(num_programs, num_rows * num_cols):
        row = idx // num_cols
        col = idx % num_cols
        fig.delaxes(axes[row, col])
    
    # Set main title
    fig.suptitle('Basic Block Attributes Distribution - All Programs', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    # Adjust layout
    plt.tight_layout()
    plt.subplots_adjust(top=0.95)
    
    # Save the integrated plot
    output_filename = "../../results/all_programs_integrated_boxplot.png"
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"\nSaved integrated plot: {output_filename}")
    # plt.show()
    
    # Create and save summary statistics
    if all_stats:
        df_summary = pd.DataFrame(all_stats)
        
        # Reorder columns for better readability
        base_cols = ['Program', 'Basic_Blocks']
        stat_cols = []
        for attr in attribute_names:
            stat_cols.extend([f'{attr}_mean', f'{attr}_median', f'{attr}_std'])
        
        df_summary = df_summary[base_cols + stat_cols]
        
        # Save to CSV
        summary_filename = "../../results/all_programs_summary_stats.csv"
        df_summary.to_csv(summary_filename, index=False)
        print(f"Saved summary statistics: {summary_filename}")
        
        # Display summary table
        print(f"\n=== Summary Statistics for All Programs ===")
        print(f"Total Programs Analyzed: {len(all_stats)}")
        print("-" * 80)
        
        # Show basic info
        basic_info = df_summary[['Program', 'Basic_Blocks']].copy()
        basic_info['Basic_Blocks'] = basic_info['Basic_Blocks'].astype(int)
        print("\nBasic Block Counts:")
        print(basic_info.to_string(index=False))
        
        # Show mean values for each attribute
        print(f"\n=== Mean Values by Attribute ===")
        mean_cols = ['Program'] + [f'{attr}_mean' for attr in attribute_names]
        mean_data = df_summary[mean_cols].copy()
        
        # Round mean values for display
        for col in mean_cols[1:]:
            mean_data[col] = mean_data[col].round(3)
        
        print(mean_data.to_string(index=False))

def create_attribute_comparison_chart(directory_path):
    """
    Create a separate comparison chart showing each attribute across all programs
    """
    attribute_names = ['cmp_num', 'mem_num', 'ins_num', 'string_num', 'imme', 'offspring', 'betweenness']
    
    # Updated to match the pattern used in main function
    pattern = os.path.join(directory_path, "*_bb2attributes_standard.json")
    json_files = glob.glob(pattern)
    
    if len(json_files) < 2:
        print("Need at least 2 files for comparison chart")
        return
    
    # Collect data from all programs
    all_program_data = {}
    
    for json_file in json_files:
        program_name = Path(json_file).stem.replace('_bb2attributes_standard', '')
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Extract attribute values from the new JSON structure
            all_attributes = []
            for bb_address, bb_data in data.items():
                if 'attributes' in bb_data and isinstance(bb_data['attributes'], list):
                    all_attributes.append(bb_data['attributes'])
            
            if all_attributes:
                attributes_by_type = list(zip(*all_attributes))
                all_program_data[program_name] = attributes_by_type
            
        except Exception as e:
            print(f"Error reading {json_file}: {e}")
            continue
    
    if len(all_program_data) < 2:
        print("Need at least 2 valid programs for comparison chart")
        return
    
    # Create comparison plots for each attribute (2 rows, 4 columns)
    fig, axes = plt.subplots(2, 4, figsize=(24, 12))
    fig.suptitle('Attribute Comparison Across All Programs', fontsize=16, fontweight='bold')
    
    axes = axes.flatten()
    
    for i, attr_name in enumerate(attribute_names):
        ax = axes[i]
        
        # Collect data for this attribute from all programs
        attr_data = []
        labels = []
        
        for program_name, attributes_by_type in all_program_data.items():
            attr_data.append(attributes_by_type[i])
            # Truncate long program names for display
            labels.append(program_name[:20] if len(program_name) > 20 else program_name)
        
        bp = ax.boxplot(attr_data, labels=labels, patch_artist=True)
        
        # Color each box differently
        colors = plt.cm.Set3(np.linspace(0, 1, len(attr_data)))
        for patch, color in zip(bp['boxes'], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        
        ax.set_title(f'{attr_name}', fontsize=14, fontweight='bold')
        ax.tick_params(axis='x', rotation=45, labelsize=10)
        ax.tick_params(axis='y', labelsize=10)
        ax.grid(True, alpha=0.3)
        # ax.set_yscale('log')
    
    # Remove the last empty subplot
    axes[-1].remove()
    
    output_filename = "../../results/attribute_comparison_chart.png"
    plt.tight_layout()
    plt.subplots_adjust(top=0.93)
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"Saved attribute comparison chart: {output_filename}")
    # plt.show()


if __name__ == "__main__":
    # Set your directory path here
    # directory = "../../benchmarks_fuzzbench/aicfg"
    # directory = "../../benchmarks_fuzzbench/aicfg820"
    directory = "../../benchmarks_fuzzbench/aicfg827"
    
    # Check if directory exists
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist!")
        print("Please update the directory path in the script.")
        exit(1)
    
    print(f"Analyzing basic block attributes in: {directory}")
    print("=" * 60)
    
    # Create integrated analysis with 4 subplots per row
    analyze_bb_attributes_integrated(directory, False)
    
    print("\n" + "=" * 60)
    print("Creating attribute comparison chart...")
    create_attribute_comparison_chart(directory)
    
    print("\nAnalysis complete!")
    print("\nGenerated files:")
    print("1. all_programs_integrated_boxplot.png - Main integrated chart")
    print("2. attribute_comparison_chart.png - Attribute comparison chart")
    print("3. all_programs_summary_stats.csv - Summary statistics")
