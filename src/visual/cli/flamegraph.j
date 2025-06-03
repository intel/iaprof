### CONTENT ###

draw-flame =
    fn (&frame row start-col width)
        if ((width >= 1) and (row > 1))
            text = (&frame 'label)

            if (width > 1)
                if (((len text) > (width - 1)) and (width > 2))
                    text = (fmt "%.." (substr text 0 (width - 3)))
                text = (substr text 0 (width - 1))
            else
                text = ""

            add-element
                rect row start-col 1 width (&frame 'color)
                    'text       : text
                    'text-color : 0x000000

            &children = (&frame 'children)

            child-offset = 0
            foreach &label (&frame 'sorted-children-labels)
                &child = (&children &label)

                child-width = (sint (((float (&child 'count)) / (float (&frame 'count))) * width))
                if (child-width < 1) (child-width = 1)

                if ((child-offset + child-width) >= width)
                    child-width = (width - child-offset)

                if (child-width > 0)
                    draw-flame &child (row - 1) (start-col + child-offset) child-width

                child-offset += child-width
                unref &child

create-elements =
    fn ()
        elements := (list)

        if (flame-graph != nil)
            draw-flame flame-graph rows 1 cols

        add-element
            text 1 1 "press 'q' to quit"
        

### INPUT ###

flame-graph = nil

new-frame =
    fn (label)
        type = 'unknown

        if (startswith label "py::")
            type = 'python
        elif (contains label "::")
            type = 'cpp
        elif (endswith label "_[k]")
            type = 'kernel
            label = (substr label 0 ((len label) - 4))
        elif (endswith label "_[g]")
            type = 'gpu-inst
            label = (substr label 0 ((len label) - 4))
        elif (endswith label "_[G]")
            type = 'gpu-symbol
            label = (substr label 0 ((len label) - 4))
        elif (label == "-")
            type = 'divider

        object
            'label                  : label
            'type                   : type
            'color                  : (get-color type (rand))
            'count                  : 0
            'children               : (object)
            'sorted-children-labels : (list)

add-flame =
    fn (&frame &stack &count)
        if (len &stack)
            fname = (&stack 0)
            erase &stack 0

            &child = (&frame 'children)
            add-flame (get-or-insert &child fname (new-frame fname)) &stack &count

        (&frame 'count) += &count

get-sorted =
    fn (&frame)
        &children = (&frame 'children)
        if (len &children)
            sorted-children-labels = (list)

            foreach label &children
                &child = (&children label)
                get-sorted &child
                append sorted-children-labels (label : ((&children label) 'count))
                unref &child

            sorted-children-labels = (sorted sorted-children-labels (fn (a b) ((a 1) > (b 1))))

            foreach &pair sorted-children-labels
                append (&frame 'sorted-children-labels) (&pair 0)

parse-flamegraph-input =
    fn ()
        flame-graph := (new-frame "all")
        
        f = (fopen-rd ((argv) 1))
        lines = (fread-lines f)
        length = (len lines)
        
        add-element
            loading-bar 1 "PROFILE"
        &profile-bar = (newest-element)
        
        add-element
            loading-bar 2 "FLAME GRAPH"
        &flame-bar = (newest-element)
        
        loading-bar-update &profile-bar 0.0
        loading-bar-update &flame-bar 0.0
        
        strings = (object)
        stacks = (object)
        
        index = 0
        foreach &line lines
            split_line = (split &line "\t")
            match (split_line 0)
                "e"
                    # No comment
                    (get-or-insert stacks (split_line 1) 0) += (parse-int (split_line 4))
                    
                "string"
                    strings <- ((split_line 1) : (split_line 2))
            
            if ((index % 100000) == 0)
                loading-bar-update &profile-bar ((float index) / length)
                
            index += 1
        loading-bar-update &profile-bar 1.0
        
        # Construct the flame graph from the stacks object
        index = 0
        length = (len stacks)
        foreach stack-str-id stacks
            flame-stack = (split (strings stack-str-id) ";")
            count = (stacks stack-str-id)
            add-flame flame-graph flame-stack count
            if ((index % 1000) == 0)
                loading-bar-update &flame-bar ((float index) / length)
            index += 1
        loading-bar-update &flame-bar 1.0
            
        fclose f
        get-sorted flame-graph
        @term:exit
        
key-actions =
    object
        "q" : (' (@term:exit) )

@on-key =
    fn (key)
        if (key in key-actions)
            (key-actions key)

@on-mouse =
    fn (type action button row col)
        if ((action == 'down) and (button == 'left))
            foreach &elem elements
                if (('on-click in &elem) and (in-element &elem row col))
                    (&elem 'on-click) &elem row col

redraw =
    fn (rows cols)
        rows := rows
        cols := cols
        create-elements
        paint

@on-init =
    fn (rows cols)
        redraw rows cols
        elements := (list)
        paint
        parse-flamegraph-input
        redraw rows cols

@on-resize =
    fn (rows cols)
        redraw rows cols
