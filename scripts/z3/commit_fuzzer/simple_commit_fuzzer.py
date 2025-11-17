#!/usr/bin/env python3

import argparse
import gc
import json
import multiprocessing
import os
import psutil
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple


class SimpleCommitFuzzer:
    EXIT_CODE_BUGS_FOUND = 10
    EXIT_CODE_UNSUPPORTED = 3
    EXIT_CODE_SUCCESS = 0
    
    RESOURCE_CONFIG = {
        'cpu_warning': 85.0,
        'cpu_critical': 95.0,
        'memory_warning': 80.0,
        'memory_critical': 90.0,
        'check_interval': 5,
        'pause_duration': 10,
        'max_process_memory_mb': 500,
    }
    
    def __init__(
        self,
        tests: List[str],
        tests_root: str,
        bugs_folder: str = "bugs",
        num_workers: int = 4,
        iterations: int = 2147483647,
        time_remaining: Optional[int] = None,
        job_start_time: Optional[float] = None,
        stop_buffer_minutes: int = 5,
        z3_old_path: Optional[str] = None,
        cvc4_path: Optional[str] = None,
        z3_path: str = "./build/z3",
        cvc5_path: Optional[str] = None,
        job_id: Optional[str] = None,
    ):
        self.tests = tests
        self.tests_root = Path(tests_root)
        self.bugs_folder = Path(bugs_folder)
        self.iterations = iterations
        self.job_id = job_id
        self.start_time = time.time()
        
        try:
            self.cpu_count = psutil.cpu_count()
        except Exception:
            self.cpu_count = 4
        
        self.num_workers = min(num_workers, self.cpu_count) if num_workers > 0 else self.cpu_count
        if num_workers > self.cpu_count:
            print(f"[WARN] Requested {num_workers} workers but only {self.cpu_count} CPU cores available, using {self.num_workers} workers", file=sys.stderr)
        
        if job_start_time is not None:
            self.time_remaining = self._compute_time_remaining(job_start_time, stop_buffer_minutes)
            print(f"[DEBUG] Job start time: {job_start_time} ({time.ctime(job_start_time)})")
            print(f"[DEBUG] Script start time: {self.start_time} ({time.ctime(self.start_time)})")
            build_time = self.start_time - job_start_time
            print(f"[DEBUG] Build time: {build_time:.1f}s ({build_time / 60:.1f} minutes)")
            print(f"[DEBUG] Stop buffer: {stop_buffer_minutes} minutes")
            print(f"[DEBUG] Computed remaining time: {self.time_remaining}s ({self.time_remaining / 60:.1f} minutes)")
        elif time_remaining is not None:
            self.time_remaining = time_remaining
            print(f"[DEBUG] Using provided time_remaining: {time_remaining}s ({time_remaining / 60:.1f} minutes)")
        else:
            self.time_remaining = None
            print("[DEBUG] No timeout set (running indefinitely)")
        
        self.z3_path = Path(z3_path)
        # self.z3_old_path = Path(z3_old_path) if z3_old_path else None
        # self.cvc4_path = Path(cvc4_path) if cvc4_path else None
        self.cvc5_path = Path(cvc5_path) if cvc5_path else None
        
        self._validate_solvers()
        self.bugs_folder.mkdir(parents=True, exist_ok=True)
        
        self.test_queue = multiprocessing.Queue()
        self.bugs_lock = multiprocessing.Lock()
        self.shutdown_event = multiprocessing.Event()
        
        self.resource_state = multiprocessing.Manager().dict({
            'cpu_percent': [0.0] * self.cpu_count,
            'memory_percent': 0.0,
            'status': 'normal',
            'paused': False,
            'last_update': time.time(),
        })
        self.resource_lock = multiprocessing.Lock()
        
        self.stats = multiprocessing.Manager().dict({
            'tests_processed': 0,
            'bugs_found': 0,
            'tests_removed_unsupported': 0,
            'tests_removed_timeout': 0,
            'tests_requeued': 0,
        })
    
    def _validate_solvers(self):
        if not self.z3_path.exists():
            raise ValueError(f"z3 not found at: {self.z3_path}")
        # if self.z3_old_path and not self.z3_old_path.exists():
        #     raise ValueError(f"z3-old not found at: {self.z3_old_path}")
        # if self.cvc4_path and not self.cvc4_path.exists():
        #     raise ValueError(f"cvc4 not found at: {self.cvc4_path}")
        if self.cvc5_path and not self.cvc5_path.exists():
            raise ValueError(f"cvc5 not found at: {self.cvc5_path}")
    
    def _monitor_resources(self):
        while not self.shutdown_event.is_set():
            try:
                try:
                    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
                    memory = psutil.virtual_memory()
                    memory_percent = memory.percent
                    
                    max_cpu = max(cpu_percent) if cpu_percent else 0.0
                    avg_cpu = sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0.0
                    
                    status = 'normal'
                    
                    if (avg_cpu >= self.RESOURCE_CONFIG['cpu_critical'] or 
                        memory_percent >= self.RESOURCE_CONFIG['memory_critical']):
                        status = 'critical'
                    elif (avg_cpu >= self.RESOURCE_CONFIG['cpu_warning'] or 
                          memory_percent >= self.RESOURCE_CONFIG['memory_warning']):
                        status = 'warning'
                    
                    with self.resource_lock:
                        self.resource_state['cpu_percent'] = cpu_percent
                        self.resource_state['memory_percent'] = memory_percent
                        self.resource_state['status'] = status
                        self.resource_state['last_update'] = time.time()
                        self.resource_state['max_cpu'] = max_cpu
                        self.resource_state['avg_cpu'] = avg_cpu
                        self.resource_state['memory_total_gb'] = memory.total / (1024**3)
                        self.resource_state['memory_used_gb'] = memory.used / (1024**3)
                    
                    if status == 'critical':
                        self._handle_critical_resources(cpu_percent, max_cpu, avg_cpu, memory_percent, memory.total, memory.used)
                    elif status == 'warning':
                        self._handle_warning_resources()
                    
                except (ImportError, AttributeError) as e:
                    print(f"[WARN] psutil not available, skipping resource monitoring: {e}", file=sys.stderr)
                    break
                
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
            except Exception as e:
                print(f"[WARN] Error in resource monitoring: {e}", file=sys.stderr)
                time.sleep(self.RESOURCE_CONFIG['check_interval'])
    
    def _handle_warning_resources(self):
        try:
            gc.collect()
        except Exception:
            pass
    
    def _handle_critical_resources(self, cpu_percent: List[float], max_cpu: float, avg_cpu: float, memory_percent: float, memory_total: int, memory_used: int):
        try:
            memory_total_gb = memory_total / (1024**3)
            memory_used_gb = memory_used / (1024**3)
            
            issues = []
            if avg_cpu >= self.RESOURCE_CONFIG['cpu_critical']:
                cpu_details = ", ".join([f"core{i+1}:{p:.1f}%" for i, p in enumerate(cpu_percent)])
                issues.append(f"CPU: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max ({cpu_details}, critical: {self.RESOURCE_CONFIG['cpu_critical']}%)")
            if memory_percent >= self.RESOURCE_CONFIG['memory_critical']:
                issues.append(f"Memory: {memory_percent:.1f}% ({memory_used_gb:.2f}GB / {memory_total_gb:.2f}GB, critical: {self.RESOURCE_CONFIG['memory_critical']}%)")
            
            if issues:
                print(f"[RESOURCE] Critical resource usage detected - {', '.join(issues)} - taking action", file=sys.stderr)
            else:
                print(f"[RESOURCE] Critical resource usage detected - CPU: {avg_cpu:.1f}% avg, {max_cpu:.1f}% max, Memory: {memory_percent:.1f}% ({memory_used_gb:.2f}GB / {memory_total_gb:.2f}GB) - taking action", file=sys.stderr)
        except Exception as e:
            print(f"[RESOURCE] Critical resource usage detected - CPU: {avg_cpu:.1f}% avg, Memory: {memory_percent:.1f}% - taking action (error formatting details: {e})", file=sys.stderr)
        
        # If memory is critical, stop immediately to preserve bugs
        if memory_percent >= self.RESOURCE_CONFIG['memory_critical']:
            self._log_bugs_summary_and_stop()
            return
        
        with self.resource_lock:
            self.resource_state['paused'] = True
        
        try:
            gc.collect()
        except Exception:
            pass
        
        try:
            main_pid = os.getpid()
            worker_pids = set()
            if hasattr(self, 'workers'):
                for w in self.workers:
                    try:
                        worker_pids.add(w.pid)
                    except (AttributeError, ValueError):
                        pass
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'ppid']):
                try:
                    proc_info = proc.info
                    if proc_info['ppid'] == main_pid or proc_info['ppid'] in worker_pids:
                        rss_mb = proc_info['memory_info'].rss / (1024 * 1024)
                        if rss_mb > self.RESOURCE_CONFIG['max_process_memory_mb']:
                            print(f"[RESOURCE] Killing process {proc_info['pid']} ({proc_info['name']}) using {rss_mb:.1f}MB", file=sys.stderr)
                            proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                    pass
        except Exception as e:
            print(f"[WARN] Error killing processes: {e}", file=sys.stderr)
        
        time.sleep(self.RESOURCE_CONFIG['pause_duration'])
        
        with self.resource_lock:
            self.resource_state['paused'] = False
    
    def _calculate_folder_size_mb(self, folder_path: Path) -> float:
        """Calculate total size of a folder in MB"""
        try:
            if folder_path.exists():
                size_bytes = sum(f.stat().st_size for f in folder_path.rglob('*') if f.is_file())
                return size_bytes / (1024 * 1024)
            else:
                return 0.0
        except Exception:
            return 0.0
    
    def _log_bugs_summary_and_stop(self):
        """Log bugs summary from all folders and stop gracefully"""
        print("\n" + "=" * 60, file=sys.stderr)
        print("CRITICAL MEMORY DETECTED - STOPPING TO PRESERVE BUGS", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        
        # Collect bugs from main bugs folder
        main_bugs = self._collect_bug_files(self.bugs_folder)
        main_bug_count = len(main_bugs)
        main_bugs_size_mb = self._calculate_folder_size_mb(self.bugs_folder)
        
        # Collect info from all worker folders
        total_worker_bugs = 0
        worker_folders_info = []
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs_folder = self.bugs_folder / f"worker_{worker_id}"
            worker_bugs = self._collect_bug_files(worker_bugs_folder)
            worker_bug_count = len(worker_bugs)
            total_worker_bugs += worker_bug_count
            
            # Calculate sizes for all worker folders
            bugs_size_mb = self._calculate_folder_size_mb(worker_bugs_folder)
            scratch_folder = Path(f"scratch_{worker_id}")
            scratch_size_mb = self._calculate_folder_size_mb(scratch_folder)
            log_folder = Path(f"logs_{worker_id}")
            log_size_mb = self._calculate_folder_size_mb(log_folder)
            
            worker_folders_info.append({
                'id': worker_id,
                'bugs': worker_bug_count,
                'bugs_size_mb': bugs_size_mb,
                'scratch_size_mb': scratch_size_mb,
                'log_size_mb': log_size_mb,
                'total_size_mb': bugs_size_mb + scratch_size_mb + log_size_mb
            })
        
        total_bugs = main_bug_count + total_worker_bugs
        
        print(f"\nBUGS SUMMARY:", file=sys.stderr)
        print(f"  Total bugs found: {total_bugs}", file=sys.stderr)
        print(f"  Main bugs folder: {main_bug_count} bugs, {main_bugs_size_mb:.2f} MB", file=sys.stderr)
        print(f"  Worker folders:", file=sys.stderr)
        for info in worker_folders_info:
            print(f"    worker_{info['id']}:", file=sys.stderr)
            print(f"      bugs: {info['bugs']} bugs, {info['bugs_size_mb']:.2f} MB", file=sys.stderr)
            print(f"      scratch: {info['scratch_size_mb']:.2f} MB", file=sys.stderr)
            print(f"      logs: {info['log_size_mb']:.2f} MB", file=sys.stderr)
            print(f"      total: {info['total_size_mb']:.2f} MB", file=sys.stderr)
        
        print(f"\nSTATISTICS:", file=sys.stderr)
        print(f"  Tests processed: {self.stats.get('tests_processed', 0)}", file=sys.stderr)
        print(f"  Bugs found: {self.stats.get('bugs_found', 0)}", file=sys.stderr)
        print(f"  Tests requeued (bugs found): {self.stats.get('tests_requeued', 0)}", file=sys.stderr)
        print(f"  Tests removed (unsupported): {self.stats.get('tests_removed_unsupported', 0)}", file=sys.stderr)
        print(f"  Tests removed (timeout): {self.stats.get('tests_removed_timeout', 0)}", file=sys.stderr)
        
        print("\n" + "=" * 60, file=sys.stderr)
        print("Stopping fuzzer to preserve found bugs...", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        
        # Stop all workers gracefully
        self.shutdown_event.set()
    
    def _check_resource_state(self) -> str:
        with self.resource_lock:
            return self.resource_state.get('status', 'normal')
    
    def _is_paused(self) -> bool:
        with self.resource_lock:
            return self.resource_state.get('paused', False)
    
    def _get_solver_clis(self) -> str:
        solvers = [f"{self.z3_path} model_validate=true"]
        # if self.z3_old_path:
        #     solvers.append(str(self.z3_old_path))
        if self.cvc5_path:
            solvers.append(f"{self.cvc5_path} --check-models --check-proofs --strings-exp")
        # if self.cvc4_path:
        #     solvers.append(str(self.cvc4_path))
        return ";".join(solvers)
    
    def _compute_time_remaining(self, job_start_time: float, stop_buffer_minutes: int) -> int:
        GITHUB_TIMEOUT = 21600
        MIN_REMAINING = 600
        
        build_time = self.start_time - job_start_time
        stop_buffer_seconds = stop_buffer_minutes * 60
        available_time = GITHUB_TIMEOUT - build_time
        remaining = available_time - stop_buffer_seconds
        
        if remaining < MIN_REMAINING:
            print(f"[DEBUG] Computed remaining time ({remaining}s) is less than minimum ({MIN_REMAINING}s), using {MIN_REMAINING}s")
            remaining = MIN_REMAINING
        
        return int(remaining)
    
    def _get_time_remaining(self) -> float:
        if self.time_remaining is None:
            return float('inf')
        return max(0.0, self.time_remaining - (time.time() - self.start_time))
    
    def _is_time_expired(self) -> bool:
        return self.time_remaining is not None and self._get_time_remaining() <= 0
    
    def _collect_bug_files(self, folder: Path) -> List[Path]:
        if not folder.exists():
            return []
        return list(folder.glob("*.smt2")) + list(folder.glob("*.smt"))
    
    def _run_typefuzz(
        self,
        test_name: str,
        worker_id: int,
        per_test_timeout: Optional[float] = None,
    ) -> Tuple[int, List[Path], float]:
        test_path = self.tests_root / test_name
        if not test_path.exists():
            print(f"[WORKER {worker_id}] Error: Test file not found: {test_path}", file=sys.stderr)
            return (1, [], 0.0)
        
        bugs_folder = self.bugs_folder / f"worker_{worker_id}"
        scratch_folder = Path(f"scratch_{worker_id}")
        log_folder = Path(f"logs_{worker_id}")
        
        for folder in [scratch_folder, log_folder]:
            shutil.rmtree(folder, ignore_errors=True)
            folder.mkdir(parents=True, exist_ok=True)
        bugs_folder.mkdir(parents=True, exist_ok=True)
        
        solver_clis = self._get_solver_clis()
        
        cmd = [
            "typefuzz",
            "-i", str(self.iterations),
            "--timeout", "120",
            "--bugs", str(bugs_folder),
            "--scratch", str(scratch_folder),
            "--logfolder", str(log_folder),
            solver_clis,
            str(test_path),
        ]
        
        print(f"[WORKER {worker_id}] Running typefuzz on: {test_name} (timeout: {per_test_timeout}s)" if per_test_timeout else f"[WORKER {worker_id}] Running typefuzz on: {test_name}")
        
        start_time = time.time()
        
        try:
            if per_test_timeout and per_test_timeout > 0:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=per_test_timeout)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True)
            
            exit_code = result.returncode
            runtime = time.time() - start_time
            bug_files = self._collect_bug_files(bugs_folder)
            return (exit_code, bug_files, runtime)
            
        except subprocess.TimeoutExpired:
            runtime = time.time() - start_time
            return (124, [], runtime)
        except Exception:
            runtime = time.time() - start_time
            return (1, [], runtime)
        finally:
            for folder in [scratch_folder, log_folder]:
                shutil.rmtree(folder, ignore_errors=True)
    
    def _handle_exit_code(
        self,
        test_name: str,
        exit_code: int,
        bug_files: List[Path],
        runtime: float,
        worker_id: int,
    ) -> str:
        if exit_code == self.EXIT_CODE_BUGS_FOUND:
            if bug_files:
                print(f"[WORKER {worker_id}] ✓ Exit code 10: Found {len(bug_files)} bug(s) on {test_name}")
                with self.bugs_lock:
                    for bug_file in bug_files:
                        try:
                            dest = self.bugs_folder / bug_file.name
                            if dest.exists():
                                timestamp = int(time.time())
                                dest = self.bugs_folder / f"{bug_file.stem}_{timestamp}{bug_file.suffix}"
                            shutil.move(str(bug_file), str(dest))
                            self.stats['bugs_found'] += 1
                        except Exception as e:
                            print(f"[WORKER {worker_id}] Warning: Failed to move bug file {bug_file}: {e}", file=sys.stderr)
            else:
                print(f"[WORKER {worker_id}] Warning: Exit code 10 but no bugs found for {test_name}", file=sys.stderr)
            return 'requeue'
        
        elif exit_code == self.EXIT_CODE_UNSUPPORTED:
            print(f"[WORKER {worker_id}] ⚠ Exit code 3: {test_name} (unsupported operation - removing)")
            self.stats['tests_removed_unsupported'] += 1
            return 'remove'
        
        elif exit_code == self.EXIT_CODE_SUCCESS:
            if not bug_files:
                print(f"[WORKER {worker_id}] Exit code 0: No bugs found on {test_name} (runtime: {runtime:.1f}s) - removing (32 timeouts)")
                self.stats['tests_removed_timeout'] += 1
                return 'remove'
            else:
                print(f"[WORKER {worker_id}] Exit code 0: {test_name} (runtime: {runtime:.1f}s) - bugs found, requeuing")
                return 'requeue'
        
        else:
            return 'continue'
    
    def _worker_process(self, worker_id: int):
        print(f"[WORKER {worker_id}] Started")
        
        while not self.shutdown_event.is_set():
            try:
                if self._is_paused():
                    resource_status = self._check_resource_state()
                    print(f"[WORKER {worker_id}] Paused due to {resource_status} resource usage", file=sys.stderr)
                    time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                    continue
                
                try:
                    test_name = self.test_queue.get(timeout=1.0)
                except Exception:
                    if self.shutdown_event.is_set() or self._is_time_expired():
                        break
                    continue
                
                if self._is_time_expired():
                    try:
                        self.test_queue.put(test_name)
                    except Exception:
                        pass
                    break
                
                resource_status = self._check_resource_state()
                if resource_status == 'warning':
                    time.sleep(2)
                elif resource_status == 'critical':
                    try:
                        self.test_queue.put(test_name)
                    except Exception:
                        pass
                    time.sleep(self.RESOURCE_CONFIG['pause_duration'])
                    continue
                
                time_remaining = self._get_time_remaining()
                exit_code, bug_files, runtime = self._run_typefuzz(
                    test_name,
                    worker_id,
                    per_test_timeout=time_remaining if self.time_remaining and time_remaining > 0 else None,
                )
                
                action = self._handle_exit_code(test_name, exit_code, bug_files, runtime, worker_id)
                
                if action == 'requeue':
                    try:
                        self.test_queue.put(test_name)
                        self.stats['tests_requeued'] += 1
                    except Exception:
                        pass
                
                self.stats['tests_processed'] += 1
                
            except Exception as e:
                print(f"[WORKER {worker_id}] Error in worker: {e}", file=sys.stderr)
                continue
        
        print(f"[WORKER {worker_id}] Stopped")
    
    def run(self):
        if not self.tests:
            print(f"No tests provided{' for job ' + self.job_id if self.job_id else ''}")
            return
        
        print(f"Running fuzzer on {len(self.tests)} test(s){' for job ' + self.job_id if self.job_id else ''}")
        print(f"Tests root: {self.tests_root}")
        print(f"Timeout: {self.time_remaining}s ({self.time_remaining // 60} minutes)" if self.time_remaining else "No timeout")
        print(f"Iterations per test: {self.iterations}")
        print(f"CPU cores: {self.cpu_count}")
        print(f"Workers: {self.num_workers}")
        print(f"Solvers: z3={self.z3_path}, cvc5={self.cvc5_path} --check-models --check-proofs --strings-exp")
        print()
        
        for test in self.tests:
            self.test_queue.put(test)
        
        workers = []
        for worker_id in range(1, self.num_workers + 1):
            worker = multiprocessing.Process(target=self._worker_process, args=(worker_id,))
            worker.start()
            workers.append(worker)
        
        self.workers = workers
        
        monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        monitor_thread.start()
        print("[DEBUG] Resource monitoring started")
        
        def signal_handler(signum, frame):
            print("\n⏰ Shutdown signal received, stopping workers...")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            if self.time_remaining:
                end_time = self.start_time + self.time_remaining
                while time.time() < end_time and any(w.is_alive() for w in workers):
                    time.sleep(1)
                if time.time() >= end_time:
                    print("⏰ Timeout reached, stopping workers...")
                    self.shutdown_event.set()
            else:
                for worker in workers:
                    worker.join()
        except KeyboardInterrupt:
            print("\n⏰ Interrupted, stopping workers...")
            self.shutdown_event.set()
        
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive():
                worker_pid = getattr(worker, 'pid', 'unknown')
                print(f"Warning: Worker {worker_pid} did not terminate, killing...")
                worker.terminate()
                worker.join(timeout=2)
                if worker.is_alive():
                    worker.kill()
        
        for worker_id in range(1, self.num_workers + 1):
            worker_bugs = self.bugs_folder / f"worker_{worker_id}"
            for bug_file in self._collect_bug_files(worker_bugs):
                try:
                    dest = self.bugs_folder / bug_file.name
                    if dest.exists():
                        timestamp = int(time.time())
                        dest = self.bugs_folder / f"{bug_file.stem}_{timestamp}{bug_file.suffix}"
                    shutil.move(str(bug_file), str(dest))
                except Exception:
                    pass
        
        print()
        print("=" * 60)
        print(f"FINAL BUG SUMMARY{' FOR JOB ' + self.job_id if self.job_id else ''}")
        print("=" * 60)
        
        bug_files = self._collect_bug_files(self.bugs_folder)
        if bug_files:
            print(f"\nFound {len(bug_files)} bug(s):")
            for i, bug_file in enumerate(bug_files, 1):
                print(f"\nBug #{i}: {bug_file}")
                print("-" * 60)
                try:
                    with open(bug_file, 'r') as f:
                        print(f.read())
                except Exception as e:
                    print(f"Error reading bug file: {e}")
                print("-" * 60)
        else:
            print("No bugs found.")
        
        print()
        print("Statistics:")
        print(f"  Tests processed: {self.stats.get('tests_processed', 0)}")
        print(f"  Bugs found: {self.stats.get('bugs_found', 0)}")
        print(f"  Tests requeued (bugs found): {self.stats.get('tests_requeued', 0)}")
        print(f"  Tests removed (unsupported): {self.stats.get('tests_removed_unsupported', 0)}")
        print(f"  Tests removed (timeout): {self.stats.get('tests_removed_timeout', 0)}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Simple commit fuzzer that runs typefuzz on tests with multiple solvers"
    )
    parser.add_argument(
        "--tests-json",
        required=True,
        help="JSON array of test names (relative to --tests-root)",
    )
    parser.add_argument(
        "--job-id",
        help="Job identifier (optional, for logging)",
    )
    parser.add_argument(
        "--tests-root",
        default="test/regress/cli",
        help="Root directory for tests (default: test/regress/cli)",
    )
    parser.add_argument(
        "--time-remaining",
        type=int,
        help="Remaining time until job timeout in seconds (legacy, use --job-start-time instead)",
    )
    parser.add_argument(
        "--job-start-time",
        type=float,
        help="Unix timestamp when the job started (for automatic time calculation)",
    )
    parser.add_argument(
        "--stop-buffer-minutes",
        type=int,
        default=5,
        help="Minutes before timeout to stop (default: 5, can be set higher for testing)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=2147483647,
        help="Number of iterations per test (default: 2147483647)",
    )
    parser.add_argument(
        "--z3-old-path",
        required=False,
        help="Path to z3-4.8.7 binary (not used, commented out)",
    )
    parser.add_argument(
        "--cvc4-path",
        required=False,
        help="Path to cvc4-1.6 binary (not used, commented out)",
    )
    parser.add_argument(
        "--z3-path",
        default="./build/z3",
        help="Path to z3 binary (default: ./build/z3)",
    )
    parser.add_argument(
        "--cvc5-path",
        help="Path to cvc5 binary (for oracle, optional)",
    )
    try:
        default_workers = psutil.cpu_count()
    except Exception:
        default_workers = 4
    
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Number of worker processes (default: {default_workers}, auto-detected from CPU cores). Each worker runs typefuzz with 4 solvers",
    )
    parser.add_argument(
        "--bugs-folder",
        default="bugs",
        help="Folder to store bugs (default: bugs)",
    )
    
    args = parser.parse_args()
    
    # Parse tests JSON
    try:
        tests = json.loads(args.tests_json)
        if not isinstance(tests, list):
            raise ValueError("tests-json must be a JSON array")
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in --tests-json: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Create and run fuzzer
    try:
        fuzzer = SimpleCommitFuzzer(
            tests=tests,
            tests_root=args.tests_root,
            bugs_folder=args.bugs_folder,
            num_workers=args.workers,
            iterations=args.iterations,
            time_remaining=args.time_remaining,
            job_start_time=args.job_start_time,
            stop_buffer_minutes=args.stop_buffer_minutes,
            z3_old_path=args.z3_old_path,
            cvc4_path=args.cvc4_path,
            z3_path=args.z3_path,
            cvc5_path=args.cvc5_path,
            job_id=args.job_id,
        )
        fuzzer.run()
        # Always exit with success
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        # Still exit with success to not fail the workflow
        sys.exit(0)


if __name__ == "__main__":
    main()

