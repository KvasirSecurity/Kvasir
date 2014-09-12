# encoding: utf-8
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Tasks controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

import logging
logger = logging.getLogger("web2py.app.kvasir")


@auth.requires_login()
def index():
    """
    Displays all tasks in a big dataTable
    """
    response.title = "%s :: Tasks" % (settings.title)
    schd = db.scheduler_task
    #schd.id.represent = lambda r,id:A(id, _href=URL('tasks', 'runs', args=id))
    fields = [
        schd.id,
        schd.task_name,
        schd.status,
        schd.function_name,
        schd.args,
        schd.vars,
        schd.start_time,
        schd.next_run_time,
        schd.stop_time,
        schd.repeats,
        schd.retry_failed,
        schd.period,
        schd.timeout,
        schd.times_run,
        schd.times_failed,
        schd.last_run_time,
        schd.group_name,
        schd.assigned_worker_name,
    ]

    rows = db(schd.id > 0).select()
    return dict(rows=rows, fields=fields)

@auth.requires_login()
def status():
    """
    task_id is the scheduler_task identifier, not the record id.
    """
    task_id = request.args(0) or redirect(URL('index'))
    task = db(db.scheduler_task.id == task_id).select().first()
    if not task:
        redirect(URL('tasks','index'))
    response.title = "%s Task :: %s" % (settings.title, task.task_name)
    return dict(task=task)

@auth.requires_signature()
@auth.requires_login()
def stop():
    """
    Uses the scheduler.stop_task() to stop a task (wow!)
    """
    task_id = request.vars.get('id') or request.get(0)
    if not task_id:
        response.flash = "No task identifer sent"
        return dict()

    try:
        task_id = int(task_id)
    except:
        response.flash = "Invalid task identifier"
        return dict()

    res = scheduler.stop_task(task_id)
    if not res:
        response.flash = "Task %s not found (result = %s)" % (task_id, res)
    else:
        response.flash = "Stopping task %s (result = %s)" % (task_id, res)
        response.headers['web2py-component-command'] = '$("#stop_button").addClass("disabled");'
    return dict()

@auth.requires_login()
def output():
    """
    task_id is the scheduler_task identifier, not the record id.
    """
    from datetime import datetime, timedelta

    task_id = request.args(0) or redirect(URL('index'))
    task = db(db.scheduler_run.task_id == task_id).select(
        join=db.scheduler_task.on(db.scheduler_run.task_id == db.scheduler_task.id)).last()
    response.title = "%s :: Task #%s :: Output" % (settings.title, task_id)

    if task:
        expiration = task.scheduler_run.start_time + timedelta(seconds=task.scheduler_task.timeout)
        return dict(
            name=task.scheduler_task.task_name,
            output=task.scheduler_run.run_output,
            status=task.scheduler_run.status,
            traceback=task.scheduler_run.traceback,
            worker=task.scheduler_run.worker_name,
            start=task.scheduler_run.start_time,
            ended=task.scheduler_run.stop_time,
            expiration=expiration,
        )
    else:
        newtask = db(db.scheduler_task.id == task_id).select().first()
        return dict(
            name=newtask.task_name,
            output="",
            status=newtask.status,
            traceback="",
            worker=newtask.assigned_worker_name,
            start="N/A",
            ended="",
        )
