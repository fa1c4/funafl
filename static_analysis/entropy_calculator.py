'''
entropy calculator code
'''
import os
import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path
import math
from typing import Dict, List, Tuple, Union

import glob
import matplotlib
# Set backend to Agg to avoid Qt display issues
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import defaultdict

class BasicBlockEntropyCalculator:
    """
    Calculate entropy weights for basic block attributes and compute scores.
    Supports both entropy-based and 2-norm scoring methods.
    Processes each file separately.
    """
    
    def __init__(self, target_directory: str):
        self.target_directory = Path(target_directory)
        
    def scan_json_files(self) -> List[Path]:
        """
        Scan directory for *_bb2attributes.json files.
        """
        json_files = list(self.target_directory.glob("*_bb2attributes.json"))
        
        if not json_files:
            raise FileNotFoundError(f"No *_bb2attributes.json files found in {self.target_directory}")
        
        print(f"Found {len(json_files)} JSON files:")
        for file in json_files:
            print(f"  - {file.name}")
            
        return json_files
    
    def load_single_file(self, file_path: Path) -> Dict:
        """
        Load a single JSON file.
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                print(f"Loaded {len(data)} basic blocks from {file_path.name}")
                return data
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            return {}
    
    def extract_attributes_matrix_single_file(self, file_data: Dict) -> Tuple[np.ndarray, List[str], List[str]]:
        """
        Extract attributes from a single file's basic blocks into a matrix.
        Returns: (attributes_matrix, block_ids, feature_names)
        """
        all_blocks = []
        block_ids = []
        
        # Collect all basic blocks from the file
        for block_addr, block_info in file_data.items():
            attributes = block_info.get('attributes', [])
            if attributes:  # Only include blocks with attributes
                all_blocks.append(attributes)
                block_ids.append(block_addr)
        
        if not all_blocks:
            raise ValueError("No attributes found in any basic blocks")
            
        # Convert to numpy array
        attributes_matrix = np.array(all_blocks, dtype=float)
        
        # Create feature names
        n_features = attributes_matrix.shape[1]
        feature_names = [f"attr_{i}" for i in range(n_features)]
        
        print(f"Extracted {attributes_matrix.shape[0]} basic blocks with {attributes_matrix.shape[1]} attributes")
        
        return attributes_matrix, block_ids, feature_names
    
    def standardize_attributes(self, attributes_matrix: np.ndarray, 
                             method: str = "max_norm") -> np.ndarray:
        """
        Standardize attributes using relative optimum membership degree.
        
        Args:
            attributes_matrix: m x n matrix of attributes
            method: "max_norm" (eq 1), "min_norm" (eq 2), or "mixed" (auto-select)
        
        Returns:
            Standardized matrix r'_ij
        """
        m, n = attributes_matrix.shape
        standardized = np.zeros_like(attributes_matrix)
        
        for j in range(n):
            col = attributes_matrix[:, j]
            
            # Handle zero columns
            if np.all(col == 0):
                standardized[:, j] = 0
                continue
                
            if method == "max_norm":
                # Equation (1): r'_ij = x_ij / max_j(x_ij)
                max_val = np.max(col)
                if max_val != 0:
                    standardized[:, j] = col / max_val
                    
            elif method == "min_norm":
                # Equation (2): r'_ij = min_j(x_ij) / x_ij
                min_val = np.min(col[col > 0])  # Exclude zeros
                if min_val > 0:
                    # Only apply to non-zero values
                    mask = col > 0
                    standardized[mask, j] = min_val / col[mask]
                    standardized[~mask, j] = 0  # Keep zeros as zeros
                    
            elif method == "mixed":
                # Auto-select based on data characteristics
                # Use max_norm for attributes where higher values are better
                # Use min_norm for attributes where lower values are better
                
                # Heuristic: if most non-zero values are small, use min_norm
                non_zero_vals = col[col > 0]
                if len(non_zero_vals) > 0:
                    mean_val = np.mean(non_zero_vals)
                    max_val = np.max(non_zero_vals)
                    
                    # If mean is much smaller than max, probably "lower is better"
                    if mean_val < 0.3 * max_val and np.min(non_zero_vals) > 0:
                        # Use min_norm (equation 2)
                        min_val = np.min(non_zero_vals)
                        mask = col > 0
                        standardized[mask, j] = min_val / col[mask]
                        standardized[~mask, j] = 0
                    else:
                        # Use max_norm (equation 1)
                        standardized[:, j] = col / max_val
            else:
                print(f'Unknown standardization method: {method}')
                exit(1)

        return standardized
    
    def calculate_entropy_weights(self, standardized_matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Calculate entropy weights for each feature.
        
        Args:
            standardized_matrix: Standardized attributes matrix r'_ij
            
        Returns:
            Tuple of (weights, entropies)
        """
        m, n = standardized_matrix.shape
        entropies = np.zeros(n)
        
        for j in range(n):
            r_col = standardized_matrix[:, j]
            
            # Calculate f_ij = r'_ij / sum_i(r'_ij) - Equation (4)
            sum_r = np.sum(r_col)
            if sum_r == 0:
                entropies[j] = 0
                continue
                
            f_ij = r_col / sum_r
            
            # Calculate entropy H_j - Equation (3)
            # H_j = -sum_i(f_ij * ln(f_ij)) / ln(m)
            entropy_sum = 0
            for i in range(m):
                if f_ij[i] > 0:  # Avoid log(0)
                    entropy_sum += f_ij[i] * math.log(f_ij[i])
                    
            entropies[j] = -entropy_sum / math.log(m) if m > 1 else 0
        
        # Calculate entropy weights w_j - Equation (5)
        # w_j = (1 - H_j) / (n - sum_j(H_j))
        sum_entropies = np.sum(entropies)
        denominator = n - sum_entropies
        
        if denominator == 0:
            # All features have maximum entropy, assign equal weights
            weights = np.ones(n) / n
        else:
            weights = (1 - entropies) / denominator
            
        # Ensure weights sum to 1
        weights = weights / np.sum(weights)
        
        return weights, entropies
    
    def calculate_2norm_scores(self, attributes_matrix: np.ndarray, 
                              block_ids: List[str]) -> Dict[str, float]:
        """
        Calculate 2-norm (Euclidean norm) scores for each basic block.
        
        Args:
            attributes_matrix: Original attributes matrix (not standardized)
            block_ids: List of block identifiers
            
        Returns:
            Dictionary mapping block_id to 2-norm score
        """
        scores = {}
        
        for i, block_id in enumerate(block_ids):
            # Calculate 2-norm: sqrt(sum(xi^2))
            attributes = attributes_matrix[i, :]
            norm_squared = np.sum(attributes * attributes)
            
            # Check for invalid scores (following C code logic)
            if norm_squared <= 0.0:
                print(f"Warning: Invalid score for block {block_id}: {norm_squared}")
                scores[block_id] = 0.0
            else:
                scores[block_id] = float(math.sqrt(norm_squared))
                
        return scores
    
    def calculate_scores(self, attributes_matrix: np.ndarray, 
                        standardized_matrix: np.ndarray,
                        weights: np.ndarray, 
                        block_ids: List[str],
                        scoring_method: str = "entropy") -> Dict[str, float]:
        """
        Calculate final scores for each basic block using specified method.
        
        Args:
            attributes_matrix: Original attributes matrix
            standardized_matrix: Standardized attributes matrix
            weights: Entropy weights for each attribute
            block_ids: List of block identifiers
            scoring_method: "entropy" or "2-norm"
            
        Returns:
            Dictionary mapping block_id to score
        """
        if scoring_method == "entropy":
            # Calculate weighted sum for each basic block using entropy weights
            scores = {}
            for i, block_id in enumerate(block_ids):
                # Score = sum(w_j * r'_ij) for all j
                score = np.sum(weights * standardized_matrix[i, :])
                scores[block_id] = float(score)
            return scores
            
        elif scoring_method == "2-norm":
            # Calculate 2-norm scores using original attributes
            return self.calculate_2norm_scores(attributes_matrix, block_ids)
            
        else:
            raise ValueError(f"Unknown scoring method: {scoring_method}. Use 'entropy' or '2-norm'")
    
    def save_standardized_data(self, file_data: Dict, standardized_matrix: np.ndarray, 
                              block_ids: List[str], target_name: str):
        """
        Save standardized attributes data.
        
        Args:
            file_data: Original file data
            standardized_matrix: Standardized attributes matrix
            block_ids: List of block identifiers
            target_name: Target name for output file
        """
        standardized_data = {}
        
        for i, block_id in enumerate(block_ids):
            if block_id in file_data:
                # Copy original data
                standardized_data[block_id] = file_data[block_id].copy()
                # Replace attributes with standardized values
                standardized_data[block_id]['attributes'] = standardized_matrix[i, :].tolist()
        
        # Save standardized data
        output_file = self.target_directory / f"{target_name}_bb2attributes_standard.json"
        with open(output_file, 'w') as f:
            json.dump(standardized_data, f, indent=2)
        
        print(f"Standardized data saved to: {output_file}")
    
    def save_analysis_results(self, results: Dict, target_name: str, scoring_method: str):
        """
        Save analysis results for a single target.
        
        Args:
            results: Analysis results dictionary
            target_name: Target name for output file
            scoring_method: Scoring method used
        """
        suffix = "entropy" if scoring_method == "entropy" else "2norm"
        output_file = self.target_directory / f"{target_name}_bb_{suffix}_analysis_results.json"
        
        # Prepare data for JSON serialization
        analysis_results = {
            'target_name': target_name,
            'scoring_method': scoring_method,
            'basic_block_scores': results['scores'],
            'sorted_scores': results['sorted_scores'][:20],  # Top 20 scores
            'summary': {
                'total_blocks': len(results['scores']),
                'max_score': max(results['scores'].values()) if results['scores'] else 0,
                'min_score': min(results['scores'].values()) if results['scores'] else 0,
                'avg_score': sum(results['scores'].values()) / len(results['scores']) if results['scores'] else 0
            }
        }
        
        # Add entropy-specific data if using entropy method
        if scoring_method == "entropy":
            analysis_results.update({
                'entropy_weights': results['weights'].tolist(),
                'entropies': results['entropies'].tolist(),
                'feature_names': results['feature_names']
            })
        
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
            
        print(f"Analysis results saved to: {output_file}")
    
    def process_single_file(self, file_path: Path, 
                           standardization_method: str = "max_norm",
                           scoring_method: str = "entropy") -> Dict[str, Union[Dict, np.ndarray]]:
        """
        Process a single file.
        
        Args:
            file_path: Path to the JSON file
            standardization_method: "max_norm", "min_norm", or "mixed"
            scoring_method: "entropy" or "2-norm"
            
        Returns:
            Dictionary containing all results for this file
        """
        # Extract target name from filename
        target_name = file_path.stem.replace('_bb2attributes', '')
        
        print(f"\n" + "=" * 60)
        print(f"Processing: {target_name} (Scoring: {scoring_method})")
        print("=" * 60)
        
        # Step 1: Load data
        print(f"\n1. Loading {file_path.name}...")
        file_data = self.load_single_file(file_path)
        if not file_data:
            print(f"Skipping {file_path.name} due to loading error")
            return {}
        
        # Step 2: Extract attributes matrix
        print("\n2. Extracting attributes matrix...")
        try:
            attributes_matrix, block_ids, feature_names = self.extract_attributes_matrix_single_file(file_data)
        except ValueError as e:
            print(f"Skipping {file_path.name}: {e}")
            return {}
        
        # Step 3: Initialize variables for entropy method
        standardized_matrix = None
        weights = None
        entropies = None
        
        if scoring_method == "entropy":
            # Step 3a: Standardize attributes (only needed for entropy method)
            print(f"\n3. Standardizing attributes using method: {standardization_method}")
            standardized_matrix = self.standardize_attributes(attributes_matrix, standardization_method)
            
            # Step 4a: Calculate entropy weights
            print("\n4. Calculating entropy weights...")
            weights, entropies = self.calculate_entropy_weights(standardized_matrix)
            
            # Step 5a: Save standardized data
            print("\n5. Saving standardized data...")
            self.save_standardized_data(file_data, standardized_matrix, block_ids, target_name)
        else:
            print(f"\n3. Using {scoring_method} method (no standardization needed)")
            # Create dummy standardized matrix for compatibility
            standardized_matrix = attributes_matrix.copy()
            weights = np.ones(attributes_matrix.shape[1])  # Dummy weights
            entropies = np.zeros(attributes_matrix.shape[1])  # Dummy entropies
        
        # Step 6: Calculate scores
        print(f"\n6. Calculating basic block scores using {scoring_method} method...")
        scores = self.calculate_scores(attributes_matrix, standardized_matrix, weights, block_ids, scoring_method)
        
        # Display results summary
        print(f"\nRESULTS SUMMARY for {target_name} ({scoring_method} method)")
        print("-" * 50)
        
        if scoring_method == "entropy":
            print(f"\nAttribute Entropy Values:")
            for i, (entropy, weight) in enumerate(zip(entropies, weights)):
                print(f"  {feature_names[i]}: H = {entropy:.4f}, w = {weight:.4f}")
        
        print(f"\nTop 10 Basic Blocks by Score:")
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        for i, (block_id, score) in enumerate(sorted_scores[:10]):
            print(f"  {i+1:2d}. {block_id}: {score:.6f}")
        
        # Prepare results
        results = {
            'target_name': target_name,
            'scoring_method': scoring_method,
            'attributes_matrix': attributes_matrix,
            'standardized_matrix': standardized_matrix,
            'block_ids': block_ids,
            'feature_names': feature_names,
            'entropies': entropies,
            'weights': weights,
            'scores': scores,
            'sorted_scores': sorted_scores
        }
        
        # Step 7: Save analysis results
        print("\n7. Saving analysis results...")
        self.save_analysis_results(results, target_name, scoring_method)
        
        return results
    
    def process_all_files(self, standardization_method: str = "mixed",
                         scoring_method: str = "entropy") -> Dict[str, Dict]:
        """
        Process all files in the directory.
        
        Args:
            standardization_method: "max_norm", "min_norm", or "mixed"
            scoring_method: "entropy" or "2-norm"
            
        Returns:
            Dictionary containing results for all files
        """
        print("=" * 80)
        print(f"Basic Block Analysis - Individual File Processing ({scoring_method} method)")
        print("=" * 80)
        
        # Scan for JSON files
        json_files = self.scan_json_files()
        
        all_results = {}
        
        # Process each file separately
        for file_path in json_files:
            try:
                results = self.process_single_file(file_path, standardization_method, scoring_method)
                if results:
                    target_name = results.get('target_name', file_path.stem)
                    all_results[target_name] = results
            except Exception as e:
                print(f"Error processing {file_path.name}: {e}")
                import traceback
                traceback.print_exc()
        
        # Summary
        print(f"\n" + "=" * 80)
        print("OVERALL SUMMARY")
        print("=" * 80)
        print(f"Successfully processed {len(all_results)} out of {len(json_files)} files using {scoring_method} method")
        
        for target_name, results in all_results.items():
            total_blocks = len(results['scores'])
            avg_score = sum(results['scores'].values()) / total_blocks if total_blocks > 0 else 0
            max_score = max(results['scores'].values()) if total_blocks > 0 else 0
            print(f"  {target_name}: {total_blocks} blocks, avg score: {avg_score:.6f}, max score: {max_score:.6f}")
        
        return all_results


def main():
    """
    Main function to run the analysis.
    """
    # Set your target directory path here
    # target_directory_path = "../../benchmarks_fuzzbench/aicfg820"
    target_directory_path = "../../benchmarks_fuzzbench/aicfg827"
    
    # Create calculator instance
    calculator = BasicBlockEntropyCalculator(target_directory_path)
    
    try:
        # Process all files with standardization method
        all_results = calculator.process_all_files(
            standardization_method="max_norm",
            scoring_method="entropy"
        )
        
        print(f"\nAnalysis completed successfully!")
        print(f"Processed {len(all_results)} targets.")
        print(f"\nOutput files created:")
        print(f"  - *_bb2attributes_standard.json (standardized data)")
        print(f"  - *_bb_entropy_analysis_results.json (analysis results)")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()


'''
analysis of basic blocks scores distribution
'''
def load_entropy_analysis_files(directory):
    """Load all *_bb_entropy_analysis_results.json files from the directory."""
    pattern = os.path.join(directory, "*_bb_entropy_analysis_results.json")
    files = glob.glob(pattern)
    
    data = {}
    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                json_data = json.load(f)
                target_name = json_data.get('target_name', os.path.basename(file_path))
                basic_block_scores = json_data.get('basic_block_scores', {})
                data[target_name] = basic_block_scores
                print(f"Loaded {len(basic_block_scores)} basic blocks from {target_name}")
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    
    return data

def calculate_score_distribution(scores, scoring_method='entropy'):
    """Calculate distribution of scores in bins"""
    bins = np.arange(0.0, 0.8, 0.02) if scoring_method == 'entropy' else np.arange(0.0, 1.1, 0.1)
    hist, _ = np.histogram(scores, bins=bins)
    return hist, bins

def analyze_distributions(data, scoring_method='entropy'):
    """Analyze score distributions for all target programs."""
    distributions = {}
    bin_labels = ['[0.0-0.02)', '[0.02-0.04)', '[0.04-0.06)', '[0.06-0.08)', '[0.08-0.1)', 
                '[0.1-0.12)', '[0.12-0.14)', '[0.14-0.16)', '[0.16-0.18)', '[0.18-0.2]',
                '[0.2-0.22)', '[0.22-0.24)', '[0.24-0.26)', '[0.26-0.28)', '[0.28-0.3)',
                '[0.3-0.32)', '[0.32-0.34)', '[0.34-0.36)', '[0.36-0.38)', '[0.38-0.4)',
                '[0.4-0.42)', '[0.42-0.44)', '[0.44-0.46)', '[0.46-0.48)', '[0.48-0.5)',
                '[0.5-0.52)', '[0.52-0.54)', '[0.54-0.56)', '[0.56-0.58)', '[0.58-0.6)',
                '[0.6-0.62)', '[0.62-0.64)', '[0.64-0.66)', '[0.66-0.68)', '[0.68-0.7)',
                '[0.7-0.72)', '[0.72-0.74)', '[0.74-0.76)', '[0.76-0.78)', '[0.78-0.8]'] if scoring_method == 'entropy' else \
                ['[0.0-0.1)', '[0.1-0.2)', '[0.2-0.3)', '[0.3-0.4)', '[0.4-0.5)', '[0.5-0.6)', '[0.6-0.7)', '[0.7-0.8)', '[0.8-0.9)', '[0.9-1.0]']

    for target_name, bb_scores in data.items():
        if not bb_scores:
            continue
            
        scores = list(bb_scores.values())
        hist, bins = calculate_score_distribution(scores, scoring_method)
        
        distributions[target_name] = {
            'histogram': hist,
            'bins': bins,
            'total_blocks': len(scores),
            'max_score': max(scores),
            'min_score': min(scores),
            'avg_score': np.mean(scores),
            'scores': scores
        }
        
        # Print statistics
        print(f"\n{target_name}:")
        print(f"  Total basic blocks: {len(scores)}")
        print(f"  Score range: [{min(scores):.6f}, {max(scores):.6f}]")
        print(f"  Average score: {np.mean(scores):.6f}")
        print("  Distribution:")
        for i, (label, count) in enumerate(zip(bin_labels, hist)):
            percentage = (count / len(scores)) * 100
            print(f"    {label}: {count:6d} blocks ({percentage:5.1f}%)")
    
    return distributions

def create_visualization(distributions, scoring_method='entropy'):
    """Create subplots showing score distributions for each target program."""
    if not distributions:
        print("No data to visualize")
        return
    
    n_targets = len(distributions)
    
    # Calculate subplot layout (roughly square)
    cols = math.ceil(math.sqrt(n_targets))
    rows = math.ceil(n_targets / cols)
    
    fig, axes = plt.subplots(rows, cols, figsize=(4*cols, 3*rows))
    fig.suptitle('Basic Block Score Distributions by Target Program', fontsize=16, fontweight='bold')
    
    # Handle case where we have only one subplot
    if n_targets == 1:
        axes = [axes]
    elif rows == 1:
        axes = [axes] if cols == 1 else axes
    else:
        axes = axes.flatten()

    # Create bin centers properly - they should have same length as histogram
    if scoring_method == 'entropy':
        bins = np.arange(0.0, 0.8, 0.02)  # [0.0, 0.02, 0.04, ..., 0.78]
        bin_centers = bins[:-1] + 0.01  # [0.01, 0.03, 0.05, ..., 0.77] - centers of intervals
        bin_labels = [f'[{bins[i]:.2f}-{bins[i+1]:.2f})' for i in range(len(bins)-1)]
    else:
        bins = np.arange(0.0, 1.1, 0.1)  # [0.0, 0.1, 0.2, ..., 1.0]
        bin_centers = bins[:-1] + 0.05  # [0.05, 0.15, 0.25, ..., 0.95] - centers of intervals
        bin_labels = [f'[{bins[i]:.1f}-{bins[i+1]:.1f})' for i in range(len(bins)-1)]
    
    for i, (target_name, dist_data) in enumerate(distributions.items()):
        ax = axes[i]
        
        # Create bar chart
        bars = ax.bar(bin_centers, dist_data['histogram'], width=0.015 if scoring_method == 'entropy' else 0.08, 
                     alpha=0.7, edgecolor='black', linewidth=0.5)
        
        # Customize subplot
        ax.set_title(f'{target_name}\n({dist_data["total_blocks"]:,} blocks)', 
                    fontsize=10, fontweight='bold')
        ax.set_xlabel('Score Range', fontsize=9)
        ax.set_ylabel('Number of Basic Blocks', fontsize=9)
        ax.set_xticks(bin_centers[::2])  # Show every other tick to avoid crowding
        ax.set_xticklabels([bin_labels[j] for j in range(0, len(bin_labels), 2)], 
                          rotation=45, ha='right', fontsize=8)
        ax.tick_params(axis='y', labelsize=8)
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add statistics text
        stats_text = f'Max: {dist_data["max_score"]:.3f}\nAvg: {dist_data["avg_score"]:.6f}'
        ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=8,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        # Color bars based on score range (higher scores in warmer colors)
        colors = plt.cm.YlOrRd(np.linspace(0.3, 1.0, len(bars)))
        for bar, color in zip(bars, colors):
            bar.set_color(color)
    
    # Hide unused subplots
    for i in range(n_targets, len(axes)):
        axes[i].set_visible(False)
    
    plt.tight_layout()
    plt.subplots_adjust(top=0.93)
    # plt.show()
    plt.savefig('../../results/bb_score_distributions.png', dpi=300)

def create_summary_table(distributions):
    """Create a summary table of all target programs."""
    print("\n" + "="*80)
    print("SUMMARY TABLE")
    print("="*80)
    print(f"{'Target':<25} {'Total Blocks':<12} {'Max Score':<10} {'Avg Score':<12} {'High Score Blocks':<15}")
    print("-" * 80)
    
    for target_name, dist_data in sorted(distributions.items()):
        # Count blocks with score > 0.1
        high_score_blocks = sum(1 for score in dist_data['scores'] if score > 0.1)
        high_score_pct = (high_score_blocks / dist_data['total_blocks']) * 100
        
        print(f"{target_name:<25} {dist_data['total_blocks']:<12,} "
              f"{dist_data['max_score']:<10.3f} {dist_data['avg_score']:<12.6f} "
              f"{high_score_blocks:<6,} ({high_score_pct:4.1f}%)")

def bbs_score_analysis(scoring_method='entropy'):
    # Directory containing the JSON files
    directory = "../../benchmarks_fuzzbench/aicfg820"
    
    print("Loading entropy analysis results...")
    data = load_entropy_analysis_files(directory)
    
    if not data:
        print("No valid files found!")
        return
    
    print(f"\nFound {len(data)} target programs")
    
    print("\nAnalyzing score distributions...")
    distributions = analyze_distributions(data, scoring_method)
    
    print("\nCreating visualization...")
    create_visualization(distributions, scoring_method)
    
    create_summary_table(distributions)


'''
origin basic blocks scores distribution
'''
def calculate_2norm_score(attributes):
    """
    Calculate 2-norm (Euclidean norm) of attributes array
    Equivalent to the C function get_score_for_array
    """
    res = sum(attr * attr for attr in attributes)
    
    if res <= 0.0:
        print(f"Error: Invalid score: {res}", file=sys.stderr)
        return None
    
    return math.sqrt(res)

def read_bb_attributes_files(directory_path):
    """
    Read all *_bb2attributes.json files in the directory
    Returns a dictionary with filename as key and scores as values
    """
    pattern = os.path.join(directory_path, "*_bb2attributes.json")
    files = glob.glob(pattern)
    
    if not files:
        print(f"No *_bb2attributes.json files found in {directory_path}")
        return {}
    
    data = {}
    
    for file_path in files:
        # Extract program name from filename
        filename = os.path.basename(file_path)
        program_name = filename.replace("_bb2attributes.json", "")
        
        try:
            with open(file_path, 'r') as f:
                bb_data = json.load(f)
            
            scores = []
            for bb_id, attributes in bb_data.items():
                score = calculate_2norm_score(attributes)
                if score is not None:
                    scores.append(score)
            
            if scores:
                data[program_name] = scores
                print(f"Loaded {len(scores)} basic blocks from {filename}")
            else:
                print(f"No valid scores found in {filename}")
                
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
    
    return data

def plot_distributions(data, save_path=None):
    """
    Create subplots showing distribution for each target program
    """
    if not data:
        print("No data to plot")
        return
    
    # Define bins [0, 10), [10, 20), ..., [190, 200)
    bins = np.arange(0, 210, 10)
    bin_labels = [f"[{bins[i]}, {bins[i+1]})" for i in range(len(bins)-1)]
    
    # Calculate number of subplots
    n_programs = len(data)
    n_cols = min(4, n_programs)  # Maximum 4 columns
    n_rows = (n_programs + n_cols - 1) // n_cols
    
    # Create figure and subplots
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(5*n_cols, 4*n_rows))
    fig.suptitle('Distribution of Basic Block Scores (2-norm)', fontsize=16)
    
    # Handle case where there's only one subplot
    if n_programs == 1:
        axes = [axes]
    elif n_rows == 1:
        axes = [axes] if n_cols == 1 else axes
    else:
        axes = axes.flatten()
    
    # Plot each program's distribution
    for idx, (program_name, scores) in enumerate(data.items()):
        ax = axes[idx]
        
        # Create histogram
        hist, _ = np.histogram(scores, bins=bins)
        
        # Plot bars
        bar_positions = np.arange(len(hist))
        bars = ax.bar(bar_positions, hist, alpha=0.7, edgecolor='black')
        
        # Customize subplot
        ax.set_title(f'{program_name}\n({len(scores)} basic blocks)', fontsize=12)
        ax.set_xlabel('Score Range')
        ax.set_ylabel('Count')
        ax.set_xticks(bar_positions)
        ax.set_xticklabels(bin_labels, rotation=45, ha='right')
        ax.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bar, count in zip(bars, hist):
            if count > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                       f'{count}', ha='center', va='bottom', fontsize=8)
        
        # Print statistics
        print(f"\n{program_name} statistics:")
        print(f"  Total basic blocks: {len(scores)}")
        print(f"  Min score: {min(scores):.4f}")
        print(f"  Max score: {max(scores):.4f}")
        print(f"  Mean score: {np.mean(scores):.4f}")
        print(f"  Median score: {np.median(scores):.4f}")
        print(f"  Std deviation: {np.std(scores):.4f}")
    
    # Hide unused subplots
    for idx in range(n_programs, len(axes)):
        axes[idx].set_visible(False)
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"\nPlot saved to: {save_path}")
    # plt.show()
    
    return fig

def origin_scores_distributions():
    # Set the directory path
    # directory_path = "../../benchmarks_fuzzbench/aicfg"
    directory_path = "../../benchmarks_fuzzbench/aicfg827"
    
    # Check if directory exists
    if not os.path.exists(directory_path):
        print(f"Directory {directory_path} does not exist.")
        print("Please update the directory_path variable in the script.")
        return
    
    print(f"Reading basic block attributes from: {directory_path}")
    
    # Read all bb2attributes files
    data = read_bb_attributes_files(directory_path)
    
    if not data:
        print("No data found. Exiting.")
        return
    
    print(f"\nLoaded data from {len(data)} programs:")
    for program, scores in data.items():
        print(f"  {program}: {len(scores)} basic blocks")
    
    # Create and display plots
    save_path = os.path.join('../../results', "ori_bb_score_distributions.png")
    plot_distributions(data, save_path)
    
    # Create summary statistics
    print("\n" + "="*60)
    print("SUMMARY STATISTICS")
    print("="*60)
    
    all_scores = []
    for scores in data.values():
        all_scores.extend(scores)
    
    print(f"Total basic blocks across all programs: {len(all_scores)}")
    print(f"Overall min score: {min(all_scores):.4f}")
    print(f"Overall max score: {max(all_scores):.4f}")
    print(f"Overall mean score: {np.mean(all_scores):.4f}")
    print(f"Overall median score: {np.median(all_scores):.4f}")
    print(f"Overall std deviation: {np.std(all_scores):.4f}")


if __name__ == "__main__":
    main()
    # bbs_score_analysis()
    # origin_scores_distributions()
