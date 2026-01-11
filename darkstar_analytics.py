"""
DARKSTAR WEB FB TOOL - Analytics Module
========================================
Analytics and reporting module
Enhanced Edition - Extended Module
"""

import os
import sys
import json
import csv
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter, defaultdict
import re

# Import utilities and API modules
from darkstar_utils import (
    ProgressTracker, BatchResult, format_file_size,
    format_duration, get_timestamp, time_ago,
    write_file_lines, append_to_file, ensure_directory
)
from darkstar_api import (
    FacebookPost, FacebookComment, FacebookUser,
    FacebookGroup, APICallResult
)

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class MetricType(Enum):
    """Types of metrics"""
    ENGAGEMENT = "engagement"
    REACH = "reach"
    IMPRESSIONS = "impressions"
    CLICKS = "clicks"
    LIKES = "likes"
    COMMENTS = "comments"
    SHARES = "shares"
    REACTIONS = "reactions"

class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    HTML = "html"
    MARKDOWN = "markdown"

@dataclass
class Metric:
    """Single metric value"""
    name: str
    value: float
    unit: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class TimeSeriesMetric:
    """Time series metric data"""
    name: str
    values: List[Tuple[datetime, float]]
    unit: str = ""
    
    def get_average(self) -> float:
        """Get average value"""
        if not self.values:
            return 0.0
        return sum(v for _, v in self.values) / len(self.values)
    
    def get_max(self) -> float:
        """Get maximum value"""
        if not self.values:
            return 0.0
        return max(v for _, v in self.values)
    
    def get_min(self) -> float:
        """Get minimum value"""
        if not self.values:
            return 0.0
        return min(v for _, v in self.values)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'values': [
                {'timestamp': ts.isoformat(), 'value': val}
                for ts, val in self.values
            ],
            'unit': self.unit,
            'average': self.get_average(),
            'max': self.get_max(),
            'min': self.get_min()
        }

@dataclass
class EngagementMetrics:
    """Engagement metrics for posts"""
    total_likes: int = 0
    total_comments: int = 0
    total_shares: int = 0
    total_reactions: int = 0
    avg_likes_per_post: float = 0.0
    avg_comments_per_post: float = 0.0
    avg_shares_per_post: float = 0.0
    engagement_rate: float = 0.0
    total_posts: int = 0
    
    def calculate_engagement_rate(self, reach: int = 0) -> float:
        """Calculate engagement rate
        
        Args:
            reach: Total reach
            
        Returns:
            Engagement rate as percentage
        """
        if reach == 0 or self.total_posts == 0:
            return 0.0
        
        total_engagement = self.total_likes + self.total_comments + self.total_shares + self.total_reactions
        self.engagement_rate = (total_engagement / reach) * 100
        return self.engagement_rate
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_likes': self.total_likes,
            'total_comments': self.total_comments,
            'total_shares': self.total_shares,
            'total_reactions': self.total_reactions,
            'avg_likes_per_post': self.avg_likes_per_post,
            'avg_comments_per_post': self.avg_comments_per_post,
            'avg_shares_per_post': self.avg_shares_per_post,
            'engagement_rate': self.engagement_rate,
            'total_posts': self.total_posts
        }

@dataclass
class ContentAnalysis:
    """Content analysis results"""
    total_posts: int = 0
    total_characters: int = 0
    avg_post_length: float = 0.0
    longest_post: int = 0
    shortest_post: int = 0
    most_used_words: List[Tuple[str, int]] = field(default_factory=list)
    post_frequency: Dict[str, int] = field(default_factory=dict)
    emoji_usage: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_posts': self.total_posts,
            'total_characters': self.total_characters,
            'avg_post_length': self.avg_post_length,
            'longest_post': self.longest_post,
            'shortest_post': self.shortest_post,
            'most_used_words': [
                {'word': word, 'count': count}
                for word, count in self.most_used_words[:10]
            ],
            'post_frequency': self.post_frequency,
            'emoji_usage': self.emoji_usage
        }

@dataclass
class AnalyticsReport:
    """Complete analytics report"""
    report_id: str
    user_id: str
    generated_at: datetime = field(default_factory=datetime.now)
    time_range: Tuple[datetime, datetime] = None
    engagement_metrics: EngagementMetrics = field(default_factory=EngagementMetrics)
    content_analysis: ContentAnalysis = field(default_factory=ContentAnalysis)
    metrics: List[Metric] = field(default_factory=list)
    time_series: List[TimeSeriesMetric] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'user_id': self.user_id,
            'generated_at': self.generated_at.isoformat(),
            'time_range': {
                'start': self.time_range[0].isoformat() if self.time_range else None,
                'end': self.time_range[1].isoformat() if self.time_range else None
            },
            'engagement_metrics': self.engagement_metrics.to_dict(),
            'content_analysis': self.content_analysis.to_dict(),
            'metrics': [m.to_dict() for m in self.metrics],
            'time_series': [ts.to_dict() for ts in self.time_series]
        }

# ============================================================================
# ANALYTICS ENGINE
# ============================================================================

class AnalyticsEngine:
    """Main analytics engine for Facebook data"""
    
    def __init__(self, user_id: str):
        """Initialize analytics engine
        
        Args:
            user_id: Facebook user ID
        """
        self.user_id = user_id
        self.posts: List[FacebookPost] = []
        self.comments: List[FacebookComment] = []
        self.users: List[FacebookUser] = []
        self.groups: List[FacebookGroup] = []
    
    def add_posts(self, posts: List[FacebookPost]) -> None:
        """Add posts to analyze
        
        Args:
            posts: List of posts
        """
        self.posts.extend(posts)
    
    def add_comments(self, comments: List[FacebookComment]) -> None:
        """Add comments to analyze
        
        Args:
            comments: List of comments
        """
        self.comments.extend(comments)
    
    def calculate_engagement_metrics(self) -> EngagementMetrics:
        """Calculate engagement metrics
        
        Returns:
            EngagementMetrics object
        """
        metrics = EngagementMetrics()
        metrics.total_posts = len(self.posts)
        
        for post in self.posts:
            metrics.total_likes += post.likes_count
            metrics.total_comments += post.comments_count
            metrics.total_shares += post.shares_count
        
        if metrics.total_posts > 0:
            metrics.avg_likes_per_post = metrics.total_likes / metrics.total_posts
            metrics.avg_comments_per_post = metrics.total_comments / metrics.total_posts
            metrics.avg_shares_per_post = metrics.total_shares / metrics.total_posts
        
        return metrics
    
    def analyze_content(self) -> ContentAnalysis:
        """Analyze content patterns
        
        Returns:
            ContentAnalysis object
        """
        analysis = ContentAnalysis()
        analysis.total_posts = len(self.posts)
        
        word_counts = Counter()
        emoji_counts = Counter()
        post_lengths = []
        
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "]+",
            flags=re.UNICODE
        )
        
        for post in self.posts:
            message = post.message
            if message:
                # Count characters
                length = len(message)
                analysis.total_characters += length
                post_lengths.append(length)
                
                # Extract and count words
                words = re.findall(r'\b\w+\b', message.lower())
                # Filter common words
                stop_words = {'the', 'and', 'is', 'in', 'to', 'of', 'a', 'for', 'it', 'on', 'with'}
                meaningful_words = [w for w in words if w not in stop_words and len(w) > 2]
                word_counts.update(meaningful_words)
                
                # Extract and count emojis
                emojis = emoji_pattern.findall(message)
                emoji_counts.update(emojis)
        
        if post_lengths:
            analysis.avg_post_length = sum(post_lengths) / len(post_lengths)
            analysis.longest_post = max(post_lengths)
            analysis.shortest_post = min(post_lengths)
        
        # Get most used words
        analysis.most_used_words = word_counts.most_common(20)
        analysis.emoji_usage = dict(emoji_counts.most_common(10))
        
        # Calculate post frequency by day
        post_dates = [
            datetime.strptime(post.created_time, '%Y-%m-%dT%H:%M:%S%z').date()
            for post in self.posts if post.created_time
        ]
        date_counts = Counter(post_dates)
        analysis.post_frequency = {
            date.isoformat(): count
            for date, count in date_counts.most_common(30)
        }
        
        return analysis
    
    def generate_report(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> AnalyticsReport:
        """Generate complete analytics report
        
        Args:
            start_date: Start date for report
            end_date: End date for report
            
        Returns:
            AnalyticsReport object
        """
        report_id = f"report_{self.user_id}_{int(time.time())}"
        
        report = AnalyticsReport(
            report_id=report_id,
            user_id=self.user_id,
            time_range=(start_date, end_date) if start_date and end_date else None
        )
        
        # Calculate metrics
        report.engagement_metrics = self.calculate_engagement_metrics()
        report.content_analysis = self.analyze_content()
        
        # Add additional metrics
        report.metrics.extend([
            Metric(name="Total Posts", value=len(self.posts), unit="count"),
            Metric(name="Total Comments", value=len(self.comments), unit="count"),
            Metric(name="Avg Post Length", value=report.content_analysis.avg_post_length, unit="characters"),
        ])
        
        return report

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self, report: AnalyticsReport):
        """Initialize report generator
        
        Args:
            report: AnalyticsReport to generate from
        """
        self.report = report
    
    def generate_json(self) -> str:
        """Generate JSON report
        
        Returns:
            JSON string
        """
        return json.dumps(self.report.to_dict(), indent=2, default=str)
    
    def generate_csv(self, filepath: str) -> bool:
        """Generate CSV report
        
        Args:
            filepath: Path to save CSV file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            ensure_directory(os.path.dirname(filepath))
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write metadata
                writer.writerow(['Report ID', self.report.report_id])
                writer.writerow(['User ID', self.report.user_id])
                writer.writerow(['Generated At', self.report.generated_at.isoformat()])
                writer.writerow([])
                
                # Write engagement metrics
                writer.writerow(['Engagement Metrics'])
                writer.writerow(['Metric', 'Value'])
                metrics = self.report.engagement_metrics.to_dict()
                for key, value in metrics.items():
                    writer.writerow([key, value])
                writer.writerow([])
                
                # Write content analysis
                writer.writerow(['Content Analysis'])
                writer.writerow(['Metric', 'Value'])
                analysis = self.report.content_analysis.to_dict()
                for key, value in analysis.items():
                    if key not in ['most_used_words', 'emoji_usage']:
                        writer.writerow([key, value])
                
            return True
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            return False
    
    def generate_txt(self, filepath: str) -> bool:
        """Generate text report
        
        Args:
            filepath: Path to save text file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            ensure_directory(os.path.dirname(filepath))
            
            with open(filepath, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("FACEBOOK ANALYTICS REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Metadata
                f.write(f"Report ID: {self.report.report_id}\n")
                f.write(f"User ID: {self.report.user_id}\n")
                f.write(f"Generated At: {self.report.generated_at.isoformat()}\n\n")
                
                # Engagement Metrics
                f.write("-" * 80 + "\n")
                f.write("ENGAGEMENT METRICS\n")
                f.write("-" * 80 + "\n")
                metrics = self.report.engagement_metrics.to_dict()
                for key, value in metrics.items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
                
                # Content Analysis
                f.write("-" * 80 + "\n")
                f.write("CONTENT ANALYSIS\n")
                f.write("-" * 80 + "\n")
                analysis = self.report.content_analysis.to_dict()
                for key, value in analysis.items():
                    if key not in ['most_used_words', 'emoji_usage', 'post_frequency']:
                        f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
                
                # Most Used Words
                f.write("-" * 80 + "\n")
                f.write("MOST USED WORDS\n")
                f.write("-" * 80 + "\n")
                for word, count in analysis['most_used_words'][:10]:
                    f.write(f"{word}: {count}\n")
                f.write("\n")
                
            return True
        except Exception as e:
            logger.error(f"Error generating TXT report: {e}")
            return False
    
    def generate_html(self, filepath: str) -> bool:
        """Generate HTML report
        
        Args:
            filepath: Path to save HTML file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            ensure_directory(os.path.dirname(filepath))
            
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Facebook Analytics Report - {self.report.report_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #1877f2;
            border-bottom: 3px solid #1877f2;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #1c1e21;
            margin-top: 30px;
            border-bottom: 2px solid #e4e6eb;
            padding-bottom: 5px;
        }}
        .metric {{
            display: inline-block;
            margin: 10px;
            padding: 15px;
            background-color: #f0f2f5;
            border-radius: 5px;
            min-width: 150px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: bold;
            color: #1877f2;
        }}
        .metric-label {{
            font-size: 14px;
            color: #65676b;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e4e6eb;
        }}
        th {{
            background-color: #f0f2f5;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Facebook Analytics Report</h1>
        <p><strong>Report ID:</strong> {self.report.report_id}</p>
        <p><strong>User ID:</strong> {self.report.user_id}</p>
        <p><strong>Generated At:</strong> {self.report.generated_at.isoformat()}</p>
        
        <h2>Engagement Metrics</h2>
        <div>
"""
            
            metrics = self.report.engagement_metrics.to_dict()
            for key, value in metrics.items():
                label = key.replace('_', ' ').title()
                html += f"""
            <div class="metric">
                <div class="metric-value">{value}</div>
                <div class="metric-label">{label}</div>
            </div>
"""
            
            html += """
        </div>
        
        <h2>Content Analysis</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
"""
            
            analysis = self.report.content_analysis.to_dict()
            for key, value in analysis.items():
                if key not in ['most_used_words', 'emoji_usage', 'post_frequency']:
                    label = key.replace('_', ' ').title()
                    html += f"""
            <tr>
                <td>{label}</td>
                <td>{value}</td>
            </tr>
"""
            
            html += """
        </table>
    </div>
</body>
</html>
"""
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
            
            return True
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return False

# ============================================================================
# EXPORTED FUNCTIONS
# ============================================================================

__all__ = [
    # Enums
    'MetricType',
    'ReportFormat',
    # Data Classes
    'Metric',
    'TimeSeriesMetric',
    'EngagementMetrics',
    'ContentAnalysis',
    'AnalyticsReport',
    # Analytics
    'AnalyticsEngine',
    # Reports
    'ReportGenerator',
]