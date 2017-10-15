int cap_disable(cap_value_t capflag)
{
cap_t mycaps;
mycaps = cap_get_proc();
if (mycaps == NULL)
        return -1;
if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &capflag, CAP_CLEAR) != 0)
        return -1;
if (cap_set_proc(mycaps) != 0)
        return -1;
return 0;
}
int cap_enable(cap_value_t capflag)
{
cap_t mycaps;
mycaps = cap_get_proc();
if (mycaps == NULL)
        return -1;
if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &capflag, CAP_SET) != 0)
        return -1;
if (cap_set_proc(mycaps) != 0)
        return -1;
return 0;
}

int cap_drop(cap_value_t capflag)
{
cap_t mycaps;
mycaps = cap_get_proc();
if (mycaps == NULL)
        return -1;
if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, &capflag, CAP_CLEAR) != 0)
        return -1;
if (cap_set_flag(mycaps, CAP_PERMITTED, 1, &capflag, CAP_CLEAR) != 0)
        return -1;
if (cap_set_proc(mycaps) != 0)
        return -1;
return 0;
}
